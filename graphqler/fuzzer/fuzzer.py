"""Class for fuzzer

1. Loads pre-generated chains from the compilation step
2. Pass 1: Run chains that contain only CREATE/QUERY nodes
3. Pass 2: Run chains that also allow UPDATE nodes
4. Pass 3: Run all chains (including DELETE/UNKNOWN)
5. Clean up
"""

from __future__ import annotations

import logging
import copy
import multiprocessing
import queue as queue_module
import sys
import threading
import time
import typing
from contextlib import nullcontext
from pathlib import Path

import cloudpickle

from graphqler import config
from graphqler.chains import Chain, ChainGenerator, ChainStep
from graphqler.graph import GraphGenerator, Node
from graphqler.output import active_store, cataloged, recording
from graphqler.utils.api import API
from graphqler.utils.file_utils import get_or_create_directory, get_or_create_file, open_output
from graphqler.utils.logging_utils import Logger
from graphqler.utils.objects_bucket import ObjectsBucket
from graphqler.utils.stats import Stats

from .engine.dengine import DEngine
from .engine.detectors import IDORChainDetector, UAFChainDetector
from .engine.fengine import FEngine
from .engine.types import Result, ResultEnum
from .engine.types.profile import RuntimeProfile
from .reporters import LLMReporter


def _spawned_worker(serialized: bytes, configuration: dict, queue) -> None:
    """Restore trusted parent state under spawn/forkserver, including live config."""
    for name, value in configuration.items():
        setattr(config, name, value)
    fuzzer, target = cloudpickle.loads(serialized)
    if hasattr(fuzzer, "logger"):
        fuzzer.logger = Logger().get_fuzzer_logger()
    for singleton, attribute in ((Stats, "stats"), (ObjectsBucket, "objects_bucket"), (FEngine, "fengine")):
        if hasattr(fuzzer, attribute):
            getattr(singleton, "bind")(getattr(fuzzer, attribute))
    fuzzer._worker_entry(target, queue)


class Fuzzer:
    def __init__(self, save_path: str, url: str, objects_bucket: ObjectsBucket | None = None):
        """Initializes the fuzzer, reading information from the compiled files

        Args:
            save_path (str): Save directory path
            url (str): URL for graphql introspection query to hit
        """
        from graphqler.utils.cli_utils import compiled_target
        url = compiled_target(save_path, url)
        self.save_path = save_path
        self.output_store = active_store()
        self.url = url
        self.logger = Logger().get_fuzzer_logger()
        self.stats = Stats()
        expected_stats = Path(save_path) / config.STATS_FILE_NAME
        if self.stats.file_path.resolve() != expected_stats.resolve() or not hasattr(self.stats, "json_file_path"):
            self.stats.set_file_paths(save_path)
        self.api = API(url, save_path)

        self.dependency_graph = GraphGenerator(save_path).get_dependency_graph()
        # Reset the FEngine singleton so it binds to the current API.  When multiple
        # Fuzzer instances are created sequentially (e.g. in run_all_experiments.py),
        # the stale singleton would otherwise keep the first API's queries/mutations,
        # causing KeyErrors for every operation in the subsequent API.
        FEngine.reset()  # ty: ignore[unresolved-attribute]
        self.fengine = FEngine(self.api)
        self.dengine = DEngine(self.api)
        self.idor_detector = IDORChainDetector()
        self.uaf_detector = UAFChainDetector()

        # Initialize runtime profiles
        self.profiles: dict[str, RuntimeProfile] = {
            "primary": RuntimeProfile(name="primary", auth_token=config.AUTHORIZATION),
            "secondary": RuntimeProfile(name="secondary", auth_token=config.IDOR_SECONDARY_AUTH),
            # post_delete uses the primary auth token — UAF tests same-user access after deletion
            "post_delete": RuntimeProfile(name="post_delete", auth_token=config.AUTHORIZATION, headers=dict(config.CUSTOM_HEADERS)),
        }
        # Add any other profiles defined in config.PROFILES
        for name, profile_data in getattr(config, "PROFILES", {}).items():
            if isinstance(profile_data, dict):
                self.profiles[name] = RuntimeProfile(
                    name=name,
                    auth_token=profile_data.get("auth_token"),
                    headers=profile_data.get("headers", {}),
                    variables=profile_data.get("variables", {})
                )
            elif isinstance(profile_data, str):
                self.profiles[name] = RuntimeProfile(name=name, auth_token=profile_data)

        if objects_bucket:
            self.objects_bucket = objects_bucket
        else:
            self.objects_bucket = ObjectsBucket(self.api)

        # Load pre-generated chains produced during compilation
        self.chains: list[Chain] = ChainGenerator().load_from_yaml(save_path, self.dependency_graph)

        # Stats about the run
        self.stats.number_of_queries = self.api.get_num_queries()
        self.stats.number_of_mutations = self.api.get_num_mutations()
        self.stats.number_of_objects = self.api.get_num_objects()

        # Optional TUI callbacks — None by default so CLI mode has zero overhead.
        # Set these before calling run() / run_chain() when using the TUI.
        self.on_chain_start: typing.Callable[[Chain], None] | None = None
        self.on_chain_done: typing.Callable[[Chain, list], None] | None = None

        # Nodes that failed due to unmet hard dependencies during chain execution;
        # re-run as standalone in the dep_retry phase after islands.
        self._dep_blocked_nodes: set[Node] = set()

    @cataloged("fuzz")
    def run(self):
        """Main function to run the fuzzer"""
        self._run_worker(self.__run_fuzz)

    def _worker_entry(self, target, queue):
        """Bind output in spawned processes and report completion or a bounded error."""
        with recording(self.output_store) if self.output_store else nullcontext():
            try:
                from graphqler.utils.request_utils import reset_session
                reset_session()
                target(queue)
            except BaseException as exc:
                queue.put((False, f"{type(exc).__name__}: {exc}".encode("utf-8")[:2000].decode("utf-8", errors="replace")))
            else:
                queue.put((True, ""))

    def _run_worker(self, target):
        """Wait for execution, join terminated processes, and propagate failures to the caller."""
        self.output_store = active_store()
        request_start = 0
        if self.output_store:
            with self.output_store.connect() as db:
                request_start = db.execute("SELECT COALESCE(MAX(id),0) FROM requests WHERE run_id=?", (self.output_store.run_id,)).fetchone()[0]
        queue = multiprocessing.Queue()
        if config.DEBUG:
            p = threading.Thread(target=self._worker_entry, args=(target, queue))
            p.daemon = True
        else:
            if multiprocessing.get_start_method() == "fork":
                p = multiprocessing.Process(target=self._worker_entry, args=(target, queue))
            else:
                try:
                    configuration = {key: copy.deepcopy(value) for key, value in vars(config).items() if key.isupper()}
                    serialized = cloudpickle.dumps((self, target))
                except BaseException:
                    queue.close()
                    queue.join_thread()
                    raise
                p = multiprocessing.Process(target=_spawned_worker, args=(serialized, configuration, queue))
        try:
            p.start()
            # Debugging runs in a thread so breakpoints work; never finalize results
            # while a thread can still mutate them.
            p.join(None if config.DEBUG else config.MAX_TIME)
            if p.is_alive():
                assert isinstance(p, multiprocessing.Process)
                p.terminate()
                p.join(5)
                if p.is_alive():
                    p.kill()
                    p.join()
                raise TimeoutError(f"Fuzzer exceeded MAX_TIME ({config.MAX_TIME}s); partial results retained")
            if isinstance(p, multiprocessing.Process) and p.exitcode != 0:
                raise RuntimeError(f"Fuzzer worker exited with status {p.exitcode}")
            try:
                success, error = queue.get(timeout=2)
            except queue_module.Empty as exc:
                raise RuntimeError("Fuzzer worker exited without a completion report") from exc
            if not success:
                raise RuntimeError(error)
            if self.output_store:
                with self.output_store.connect() as db:
                    total, responses = db.execute("SELECT COUNT(*),SUM(status_code IS NOT NULL AND error IS NULL) FROM requests WHERE run_id=? AND id>?",
                                                  (self.output_store.run_id, request_start)).fetchone()
                if total and not responses:
                    raise RuntimeError("Fuzzing failed: no usable HTTP responses received; inspect recorded transport errors")
        finally:
            if isinstance(p, multiprocessing.Process) and p.is_alive():
                p.terminate()
                p.join(5)
                if p.is_alive():
                    p.kill()
                    p.join()
            queue.close()
            queue.join_thread()
            if isinstance(p, multiprocessing.Process) and p.pid is not None:
                p.close()

    @cataloged("chain")
    def run_chain(self, chain: Chain) -> None:
        """Execute a single chain (public API for use by the TUI chain explorer).

        Args:
            chain (Chain): The chain to execute.
        """
        self.__run_chain(chain)

    @cataloged("single")
    def run_single(self, node_name: str):
        """Runs a single node

        Args:
            node_name (str): The name of the node
        """
        node = [n for n in self.dependency_graph.nodes if n.name == node_name]
        if len(node) == 0:
            print(f"(F) Node `{node_name}` not found")
            self.logger.error(f"Node `{node_name}` not found")
            raise ValueError(f"Node `{node_name}` not found")

        self.stats.start_time = time.time()
        self.__run_nodes(node)
        self.logger.info("Completed fuzzing")
        self.stats.print_results()
        self.stats.save()
        self.stats.save_eval_summary()
        self.objects_bucket.save()

    @cataloged("idor")
    def run_idor_only(self):
        """Run only the IDOR chain phase, skipping regular fuzzing.

        Useful when a full fuzz run has already been done and you only want
        to re-exercise the IDOR chains (e.g., against a fresh API state).
        """
        self._run_worker(self.__run_idor_steps)

    def __run_idor_steps(self, queue: multiprocessing.Queue):
        """Run only IDOR chains (no regular fuzzing, no island nodes, no API-level detections)."""
        self.stats.start_time = time.time()

        idor_chains = [c for c in self.chains if c.is_multi_profile]

        if not idor_chains:
            print("(F) No IDOR chains found — run with --mode compile first and ensure --idor-auth is set")
            self.logger.warning("No IDOR chains found in compiled/chains/ — ensure --idor-auth is set during compilation")
        else:
            print(f"(F) Running {len(idor_chains)} IDOR candidate chain(s)")
            self.logger.info(f"Running {len(idor_chains)} IDOR candidate chain(s)")
            for chain in idor_chains:
                self.__run_chain(chain)
            self.logger.info("Completed IDOR chain phase")

        self.logger.info("Completed IDOR-only run")
        self.stats.print_results()
        self.stats.save()
        self.objects_bucket.save()

    def __run_fuzz(self, queue: multiprocessing.Queue):
        """Runs the fuzzer using pre-generated chains. Steps:
        1. Execute all chains up to MAX_FUZZING_ITERATIONS times (or until MAX_TIME)
        2. Run any nodes not covered by chains (island nodes) — once only
        3. Run detections on the overall API
        4. Finish

        When USE_DEPENDENCY_GRAPH=False (ablation baseline), skip chain ordering entirely
        and run all nodes directly without any dependency guidance.

        Args:
            queue (multiprocessing.Queue): Queue for communicating back to the parent process
        """
        self.stats.start_time = time.time()

        # Single background thread that refreshes the progress line for the entire run
        stop_progress = threading.Event()
        def _refresh_progress():
            while not stop_progress.is_set():
                self.stats.print_running_stats()
                stop_progress.wait(1.0)

        progress_thread = threading.Thread(target=_refresh_progress, daemon=True)
        progress_thread.start()

        try:
            if not config.USE_DEPENDENCY_GRAPH:
                self.logger.info("USE_DEPENDENCY_GRAPH=False: running all nodes directly (ablation mode — no chain ordering)")
                uncovered_nodes = list(self.dependency_graph.nodes)
            elif self.chains:
                max_iter = max(1, config.MAX_FUZZING_ITERATIONS)
                self.stats.chains_total = len(self.chains)
                self.stats.total_iterations = max_iter
                self.logger.info(f"Running {len(self.chains)} pre-generated chains for up to {max_iter} iteration(s)")
                for iteration in range(max_iter):
                    if time.time() - self.stats.start_time >= config.MAX_TIME:
                        self.logger.info(f"MAX_TIME reached during iteration {iteration + 1} — stopping chain loop early")
                        break
                    self.stats.current_iteration = iteration + 1
                    self.stats.chains_completed = 0
                    self.logger.info(f"Chain iteration {iteration + 1}/{max_iter}")
                    for chain in self.chains:
                        self.__run_chain(chain)
                        self.stats.chains_completed += 1
                self.logger.info("Completed all chain iterations")

                chained_nodes: set[Node] = {node for chain in self.chains for node in chain.nodes}
                uncovered_nodes = [node for node in self.dependency_graph.nodes if node not in chained_nodes]

                # Nodes that only ever appear as inner (non-last) primary chain steps are never
                # fuzzed during chain execution (the last-primary-node-only design) and are not
                # islands (they ARE in chains).  Add them to uncovered_nodes so the island phase
                # fuzz-tests them at least once.
                last_primary_nodes: set[Node] = set()
                for chain in self.chains:
                    for step in reversed(chain.steps):
                        if step.profile_name == "primary":
                            last_primary_nodes.add(step.node)
                            break
                all_chain_primary_nodes: set[Node] = {step.node for chain in self.chains for step in chain.steps if step.profile_name == "primary"}
                inner_only_nodes = all_chain_primary_nodes - last_primary_nodes
                already_queued = set(uncovered_nodes)
                uncovered_nodes.extend(node for node in inner_only_nodes if node not in already_queued)
            else:
                self.logger.warning("No chains found — falling back to running all nodes directly")
                uncovered_nodes = list(self.dependency_graph.nodes)

            if uncovered_nodes:
                self.logger.info(f"Running {len(uncovered_nodes)} uncovered node(s)")
                self.stats.phase = "islands"
                self.stats.islands_total = len(uncovered_nodes)
                self.stats.islands_completed = 0
                self.__run_nodes(uncovered_nodes)

            # Dep-retry phase: re-run nodes that failed every chain attempt due to unmet hard
            # dependencies, now using the globally shared objects_bucket (populated by islands
            # and any successful chain steps) and bypassing hard-dep checks so they get a
            # genuine attempt with whatever objects are available (or random fallbacks).
            dep_retry_nodes = [
                node for node in self._dep_blocked_nodes
                if f"{node.graphql_type}|{node.name}" not in self.stats.successful_nodes
            ]
            if dep_retry_nodes:
                self.logger.info(f"Dep-retry phase: retrying {len(dep_retry_nodes)} node(s) that always had unmet hard dependencies")
                self.stats.phase = "dep_retry"
                self.stats.dep_retry_total = len(dep_retry_nodes)
                self.stats.dep_retry_completed = 0
                for node in dep_retry_nodes:
                    self.logger.info(f"[dep_retry] Running node: {node}")
                    node_start = time.time()
                    _response, result = self.fengine.run_minimal_payload(node.name, self.objects_bucket, node.graphql_type, check_hard_depends_on=False)
                    self.stats.record_node_timing(node, time.time() - node_start)
                    self.stats.update_stats_from_result(node, result)
                    self.fengine.run_maximal_payload(node.name, self.objects_bucket, node.graphql_type, check_hard_depends_on=False)
                    self.__detect_vulnerabilities_on_node(node, self.objects_bucket)
                    self.stats.dep_retry_completed += 1

            # Detections
            self.stats.phase = "detections"
            if not (config.SKIP_INJECTION_ATTACKS and config.SKIP_MISC_ATTACKS and config.SKIP_DOS_ATTACKS and config.SKIP_ENUMERATION_ATTACKS):
                self.dengine.run_detections_on_api()
                self.logger.info("Completed running detections on the overall API")

            # LLM report (opt-in via config.LLM_ENABLE_REPORTER)
            if config.LLM_ENABLE_REPORTER:
                LLMReporter(self.save_path, self.url).generate()
        finally:
            stop_progress.set()
            progress_thread.join()
            if sys.stdout.isatty():
                print()  # move cursor past the progress line

        # Finish
        self.logger.info("Completed fuzzing")
        self.logger.info(f"Objects bucket: {self.objects_bucket}")
        self.stats.print_results()
        self.stats.save()
        self.stats.save_eval_summary()
        self.objects_bucket.save()

    def __run_chain(self, chain: Chain):
        """Executes every step in the chain sequentially using a fresh, isolated ObjectsBucket.

        Each chain is fully self-sufficient, so its bucket starts completely empty.
        Each step specifies its runtime profile name, which maps to a RuntimeProfile object
        containing auth tokens and other variables.

        A per-chain log folder is created at ``logs/chain_logs/<chain.id>/`` containing:
        - ``chain.txt``:  pretty-printed chain path (nodes → nodes)
        - ``fuzzer.log``: all fuzzer-level log records produced during this chain's execution

        Args:
            chain (Chain): The chain to execute.
        """
        bucket_cls = typing.cast(typing.Any, getattr(ObjectsBucket, "__wrapped__", ObjectsBucket))
        fresh_bucket: ObjectsBucket = bucket_cls(self.api)
        results: list[tuple[ChainStep, Result]] = []
        pre_delete_snapshot: ObjectsBucket | None = None

        # Index of the last primary step — fuzz/detect runs only on this step so that
        # inner primary nodes (setup steps) don't multiply API calls.  Inner-only nodes
        # that never appear as the last primary step in any chain are added to uncovered_nodes
        # in __run_fuzz so they still get fuzz-tested in the island phase.
        primary_indices = [i for i, s in enumerate(chain.steps) if s.profile_name == "primary"]
        last_primary_index = primary_indices[-1] if primary_indices else -1

        # --- per-chain log setup ---
        chain_log_dir = Path(config.OUTPUT_DIRECTORY) / config.CHAIN_LOGS_DIR_NAME / str(len(chain.steps)) / chain.id
        get_or_create_directory(chain_log_dir)

        # Write chain.txt with a human-readable description of the chain path
        chain_path_str = " -> ".join(repr(step) for step in chain.steps)
        chain_txt_lines = [
            f"Chain ID : {chain.id}",
            f"Path     : {chain_path_str}",
        ]
        if chain.confidence < 1.0:
            chain_txt_lines.append(f"Confidence: {chain.confidence:.4f}")
        if chain.reason:
            chain_txt_lines.append(f"Reason   : {chain.reason}")
        with open_output(chain_log_dir / "chain.txt") as description:
            description.write("\n".join(chain_txt_lines) + "\n")

        # Temporarily add a FileHandler to the 'fuzzer' logger so that all log records
        # produced during this chain (including from FEngine) land in the chain's fuzzer.log.
        chain_log_path = get_or_create_file(chain_log_dir / "fuzzer.log")
        chain_file_handler = logging.FileHandler(chain_log_path)
        formatter = logging.Formatter("[%(levelname)s][%(asctime)s][%(name)s]:%(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        chain_file_handler.setFormatter(formatter)
        fuzzer_logger = logging.getLogger("fuzzer")
        fuzzer_logger.addHandler(chain_file_handler)

        # Log the chain header as the first entry in the chain's fuzzer.log
        self.logger.info(f"=== Chain start: {chain_path_str} ===")
        self.logger.info(f"Running chain: {chain}")
        try:
            if self.on_chain_start:
                self.on_chain_start(chain)
            for i, step in enumerate(chain.steps):
                node = step.node
                if node.name in config.SKIP_NODES:
                    continue

                visit_path = [s.node for s in chain.steps[: i + 1]]

                # IDOR transition check: abort if setup produced nothing before first secondary (attacker) node.
                # Only applies to "secondary" profile (cross-user IDOR testing), not "post_delete" (UAF testing),
                # because UAF chains intentionally continue after deletion even when the bucket may be empty.
                if step.profile_name == "secondary" and i > 0 and chain.steps[i - 1].profile_name == "primary" and fresh_bucket.is_empty():
                    self.logger.info(f"[{step.profile_name}] Setup phase produced no objects — aborting chain")
                    break

                # Select profile
                profile = self.profiles.get(step.profile_name)
                if not profile:
                    self.logger.error(f"Profile '{step.profile_name}' not found — skipping step")
                    continue
                if step.profile_name not in {"primary", "post_delete"} and not profile.auth_token and not profile.headers:
                    self.logger.warning(
                        f"Profile '{step.profile_name}' has no auth token configured — aborting chain "
                        f"(set IDOR_SECONDARY_AUTH in your config to enable IDOR chain testing)"
                    )
                    break

                if step.profile_name == "post_delete":
                    # Use the pre-delete snapshot so the materializer can still resolve the object ID
                    # that was removed from the live bucket by the preceding DELETE step.
                    bucket_for_step = pre_delete_snapshot if pre_delete_snapshot is not None else fresh_bucket

                    if config.DEBUG:
                        snapshot_empty = pre_delete_snapshot is None or pre_delete_snapshot.is_empty()
                        self.logger.debug("Post-delete step: node=%s, snapshot_available=%s", node.name, not snapshot_empty)

                    self.logger.info(f"[post_delete][test] Running node with post-delete profile: {node}")
                    _response, result = self.fengine.run_minimal_payload_with_profile(
                        node.name, bucket_for_step, node.graphql_type, profile
                    )

                    if config.DEBUG:
                        self.logger.debug("Post-delete result: success=%s", result.success)

                    results.append((step, result))
                elif step.profile_name != "primary":
                    # Multi-profile test phase (e.g. secondary / IDOR)
                    self.logger.info(f"[{step.profile_name}][test] Running node with profile '{step.profile_name}': {node}")
                    _response, result = self.fengine.run_minimal_payload_with_profile(
                        node.name, fresh_bucket, node.graphql_type, profile
                    )
                    results.append((step, result))
                else:
                    # Regular primary phase — snapshot bucket before DELETE so UAF post_delete step can use it
                    next_step = chain.steps[i + 1] if i + 1 < len(chain.steps) else None
                    if next_step is not None and next_step.profile_name == "post_delete":
                        pre_delete_snapshot = fresh_bucket.clone()
                        if config.DEBUG:
                            self.logger.debug("Saved bucket before DELETE step: %s", node.name)

                    self.logger.info(f"[chain] Running node: {node}")
                    node_start = time.time()
                    _next_paths, result = self.__evaluate(node, visit_path, objects_bucket=fresh_bucket)
                    self.stats.record_node_timing(node, time.time() - node_start)
                    self.stats.update_stats_from_result(node, result)
                    if result.result_enum == ResultEnum.HARD_DEPENDENCY_NOT_MET:
                        self._dep_blocked_nodes.add(node)
                    if i == last_primary_index:
                        self.__fuzz(node, visit_path, objects_bucket=fresh_bucket)
                        self.__detect_vulnerabilities_on_node(node, fresh_bucket)
                    results.append((step, result))
                    if not result.success:
                        self.logger.info(f"[chain] Node {node} failed — stopping chain execution early")
                        # All subsequent primary non-Object steps were skipped because this node
                        # failed; mark them as dep-blocked so the dep_retry phase can attempt them.
                        for future_step in chain.steps[i + 1:]:
                            if future_step.profile_name == "primary" and future_step.node.graphql_type != "Object":
                                self._dep_blocked_nodes.add(future_step.node)
                        break

            # Post-execution analysis
            self.idor_detector.detect(chain, results, self.stats)
            self.uaf_detector.detect(chain, results, self.stats)
            if self.on_chain_done:
                self.on_chain_done(chain, results)
        finally:
            # Each chain still starts empty; retain its observations for the final
            # report and the subsequent island/dependency-retry phase.
            self.objects_bucket.merge(fresh_bucket)
            # Always remove the per-chain handler so the FD is released and logs
            # don't bleed into subsequent chains even if an exception occurred.
            self.logger.info(f"=== Chain end: {chain_path_str} ===")
            fuzzer_logger.removeHandler(chain_file_handler)
            chain_file_handler.close()

    def __run_nodes(self, nodes: list[Node]):
        """Runs the nodes given in the list

        Args:
            nodes (list[Node]): List of nodes to run

        Raises:
            Exception: If the GraphQL type of the node is unknown
        """
        for node in nodes:
            if node.name in config.SKIP_NODES:
                continue
            self.logger.info(f"[island] Running node: {node}")
            node_start = time.time()
            _next_paths, result = self.__evaluate(node, [node])
            self.stats.record_node_timing(node, time.time() - node_start)
            self.stats.update_stats_from_result(node, result)
            self.__fuzz(node, [node])
            self.__detect_vulnerabilities_on_node(node, self.objects_bucket)
            self.stats.islands_completed += 1

    def __evaluate(self, node: Node, visit_path: list[Node], objects_bucket: ObjectsBucket | None = None) -> tuple[list[list[Node]], Result]:
        """Evaluates the node

        Args:
            node (Node): The node to evaluate
            visit_path (list[Node]): The path of nodes visited so far
            objects_bucket (ObjectsBucket, optional): The objects bucket to use. Defaults to self.objects_bucket.

        Returns:
            tuple[list[list[Node]], Result]: The next paths to visit, and the result of the evaluation
        """
        if objects_bucket is None:
            objects_bucket = self.objects_bucket

        if node.graphql_type == "Query":
            _response, result = self.fengine.run_minimal_payload(node.name, objects_bucket, "Query")
            return [], result
        elif node.graphql_type == "Mutation":
            _response, result = self.fengine.run_minimal_payload(node.name, objects_bucket, "Mutation")
            return [], result
        elif node.graphql_type == "Subscription":
            if not config.SKIP_SUBSCRIPTIONS:
                _events, result = self.fengine.run_subscription_payload(node.name, objects_bucket)
                return [], result
            return [], Result(ResultEnum.GENERAL_SUCCESS)
        elif node.graphql_type == "Object":
            return [], Result(ResultEnum.GENERAL_SUCCESS)
        else:
            raise Exception(f"Unknown GraphQL type: {node.graphql_type}")

    def __fuzz(self, node: Node, visit_path: list[Node], objects_bucket: ObjectsBucket | None = None):
        """Fuzzes the node

        Args:
            node (Node): The node to fuzz
            visit_path (list[Node]): The path of nodes visited so far
            objects_bucket (ObjectsBucket, optional): The objects bucket to use. Defaults to self.objects_bucket.
        """
        if objects_bucket is None:
            objects_bucket = self.objects_bucket

        if node.graphql_type == "Query" or node.graphql_type == "Mutation":
            self.fengine.run_maximal_payload(node.name, objects_bucket, node.graphql_type)
            if not config.SKIP_DOS_ATTACKS:
                self.fengine.run_dos_payloads(node.name, objects_bucket, node.graphql_type)
        # Subscription nodes are handled in __evaluate (WebSocket, no maximal/DOS variants)

    def __detect_vulnerabilities_on_node(self, node: Node, objects_bucket: ObjectsBucket):
        """Detects vulnerabilities on the node

        Args:
            node (Node): The node to detect vulnerabilities on
            objects_bucket (ObjectsBucket): The objects bucket to use
        """
        if node.graphql_type == "Query" or node.graphql_type == "Mutation":
            self.dengine.run_detections_on_graphql_object(node, objects_bucket, node.graphql_type)
        # Subscription detection is a future enhancement
