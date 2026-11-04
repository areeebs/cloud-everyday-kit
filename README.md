# Cloud Everyday Kit

Three small, local-first checks for recurring cloud work: compare billing CSVs, review AWS IAM policies, and inspect Kubernetes YAML. The tools only read local files. They do not connect to cloud accounts or change infrastructure.

> **Status:** Early learning project. Findings are review prompts, not proof that a policy or deployment is unsafe or safe.

## Install

Requires Python 3.9+. IAM and cost commands use only the standard library. Kubernetes YAML checks need PyYAML:

```sh
python3 -m pip install -r requirements.txt
```

## Cost CSV comparison

Use an AWS Cost Explorer CSV export or a CSV with `period,service,cost` columns:

```sh
python3 cloudkit.py cost examples/monthly-costs.csv
```

It compares the two latest periods and sorts services by largest spend increase. Keep the same currency in both periods and confirm the currency from your export; the tool does not convert currencies, forecast bills, or connect to the AWS Cost Explorer API.

## IAM policy review

```sh
python3 cloudkit.py iam examples/iam-policy.json
```

Checks allow statements for wildcard actions/resources and broad `PassRole`, `NotAction`, or `NotResource` use. IAM evaluation is more complex than these checks; a finding needs review in the context of the complete policy and its conditions.

## Kubernetes manifest review

```sh
python3 cloudkit.py kube examples/workload.yaml
```

Checks a short list of deployment settings: privileged containers, hostPath volumes, missing CPU/memory requests or limits, mutable image tags, and `LoadBalancer` services. It does not connect to a cluster.

Each command supports `--json`. High-severity IAM or Kubernetes findings return exit status 1; malformed inputs return status 2.

## Relationship to the other tools

This kit adds cost, IAM, and Kubernetes checks to the separate [Compose Safety Check](https://github.com/areeebs/compose-safety-check) and [Terraform Plan Brief](https://github.com/areeebs/terraform-plan-brief) projects. Together, the five tools cover common checks before or during cloud deployment.

## Safety and privacy

- No cloud credentials are needed. No network calls are made.
- Files stay on your computer. Do not commit real billing exports or policies; they may contain account details.
- The tools make no changes to cloud resources or local input files.
- A clean result is not a security certification. Read the complete policy, manifest, or bill before acting.

## Contributing

Please use synthetic sample files and report the exact configuration shape that caused a confusing result. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
