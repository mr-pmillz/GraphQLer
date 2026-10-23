# Python API

`graphqler.core.compile_and_fuzz` runs the full compile + fuzz pipeline from Python:

```python
from graphqler.core import compile_and_fuzz

results = compile_and_fuzz(
    path="graphqler-output",
    url="http://localhost:4000/graphql",
    input_config={"MAX_TIME": 600, "SKIP_DOS_ATTACKS": True},
)

stats = results["stats"]
print(stats.number_of_successes, stats.number_of_failures)
print(list(results["api"].queries))
```

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `path` | `str` | Directory where all outputs are written |
| `url` | `str` | GraphQL endpoint |
| `input_config` | `dict \| None` | Overrides for any [configuration](configuration.md) variable, keyed by name |

## Return value

A `dict` with:

| Key | Type | Contents |
|---|---|---|
| `objects_bucket` | `ObjectsBucket` | Objects collected during fuzzing |
| `stats` | `Stats` | Fuzzing statistics and vulnerabilities |
| `api` | `API` | Parsed schema: `queries`, `mutations`, `objects`, `input_objects`, `enums`, `unions`, `interfaces` |
| `results` | `dict` | `{ endpoint: set[Result] }` |
| `database` | `str` | Path to the durable SQLite result catalog |
| `run_id` | `str` | Identity of this pipeline invocation |

The complete Python pipeline shares one run, including schema compilation and chain
generation. Standalone compiler/fuzzer methods also create catalogs. To group
several lower-level calls into one run, wrap them in
`graphqler.output.scan_run(path, url, "run")`. See [output contracts](output.md).

!!! note

    Configuration lives in the module-level `graphqler.config`, so only one configuration can be active per process.
