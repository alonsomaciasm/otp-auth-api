import fcntl
import json
import os
from typing import Dict
from fastapi import APIRouter, Response, status
from app.core.logging import logger

METRICS_FILE_PATH = "/tmp/shared_prometheus_metrics.json"


class SharedPrometheusMetricsCollector:
    """
    Unified Multi-Worker Prometheus Metrics Collector.
    Uses atomic file locking on /tmp/shared_prometheus_metrics.json to aggregate counters
    across multiple Granian ASGI worker processes without value oscillation.
    """

    def __init__(self):
        self._init_storage()

    def _init_storage(self):
        """Initializes the shared metrics JSON file if not present."""
        if not os.path.exists(METRICS_FILE_PATH):
            default_data = {
                "http_requests_total": {},
                "pow_challenges_issued_total": 0,
                "pow_challenges_verified_total": 0,
                "pow_challenges_failed_total": 0,
                "rba_evaluations_total": {"low": 0, "medium": 0, "high": 0},
                "dag_revocations_total": 0,
            }
            try:
                with open(METRICS_FILE_PATH, "w") as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    json.dump(default_data, f)
                    fcntl.flock(f, fcntl.LOCK_UN)
            except Exception as e:
                logger.error("Failed to initialize shared metrics file", error=str(e))

    def _read_data(self) -> Dict:
        """Reads shared metric counters with shared file lock."""
        if not os.path.exists(METRICS_FILE_PATH):
            self._init_storage()

        try:
            with open(METRICS_FILE_PATH, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                data = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
                return data
        except Exception as e:
            logger.error("Failed to read shared metrics file", error=str(e))
            return {
                "http_requests_total": {},
                "pow_challenges_issued_total": 0,
                "pow_challenges_verified_total": 0,
                "pow_challenges_failed_total": 0,
                "rba_evaluations_total": {"low": 0, "medium": 0, "high": 0},
                "dag_revocations_total": 0,
            }

    def _write_data(self, data: Dict):
        """Writes updated metric counters with exclusive file lock."""
        try:
            with open(METRICS_FILE_PATH, "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(data, f)
                fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            logger.error("Failed to write shared metrics file", error=str(e))

    def record_http_request(self, method: str, path: str, status_code: int):
        data = self._read_data()
        key = f"{method}:{path}:{status_code}"
        data["http_requests_total"][key] = data["http_requests_total"].get(key, 0) + 1
        self._write_data(data)

    def record_pow_issued(self):
        data = self._read_data()
        data["pow_challenges_issued_total"] += 1
        self._write_data(data)

    def record_pow_verified(self):
        data = self._read_data()
        data["pow_challenges_verified_total"] += 1
        self._write_data(data)

    def record_pow_failed(self):
        data = self._read_data()
        data["pow_challenges_failed_total"] += 1
        self._write_data(data)

    def record_rba_evaluation(self, risk_level: str):
        data = self._read_data()
        if risk_level in data["rba_evaluations_total"]:
            data["rba_evaluations_total"][risk_level] += 1
        self._write_data(data)

    def record_dag_revocation(self):
        data = self._read_data()
        data["dag_revocations_total"] += 1
        self._write_data(data)

    def generate_prometheus_format(self) -> str:
        data = self._read_data()
        lines = [
            "# HELP http_requests_total Total count of HTTP requests handled by the API",
            "# TYPE http_requests_total counter",
        ]
        for key, val in data.get("http_requests_total", {}).items():
            method, path, status_code = key.split(":")
            lines.append(f'http_requests_total{{method="{method}",path="{path}",status="{status_code}"}} {val}')

        lines.extend([
            "",
            "# HELP pow_challenges_issued_total Total count of PoW challenges generated",
            "# TYPE pow_challenges_issued_total counter",
            f"pow_challenges_issued_total {data.get('pow_challenges_issued_total', 0)}",
            "",
            "# HELP pow_challenges_verified_total Total count of successfully verified PoW nonces",
            "# TYPE pow_challenges_verified_total counter",
            f"pow_challenges_verified_total {data.get('pow_challenges_verified_total', 0)}",
            "",
            "# HELP pow_challenges_failed_total Total count of failed PoW verifications",
            "# TYPE pow_challenges_failed_total counter",
            f"pow_challenges_failed_total {data.get('pow_challenges_failed_total', 0)}",
            "",
            "# HELP rba_evaluations_total Total count of Risk-Based OTP evaluations by risk level",
            "# TYPE rba_evaluations_total counter",
        ])

        for level, count in data.get("rba_evaluations_total", {}).items():
            lines.append(f'rba_evaluations_total{{risk_level="{level}"}} {count}')

        lines.extend([
            "",
            "# HELP dag_revocations_total Total count of DAG token family tree revocations due to token reuse",
            "# TYPE dag_revocations_total counter",
            f"dag_revocations_total {data.get('dag_revocations_total', 0)}",
            "",
        ])

        return "\n".join(lines)


metrics_collector = SharedPrometheusMetricsCollector()

router = APIRouter()


@router.get(
    "/metrics",
    status_code=status.HTTP_200_OK,
    summary="Prometheus Metrics Endpoint",
    include_in_schema=True,
)
async def get_prometheus_metrics():
    """
    Exposes real-time aggregated API metrics across all Granian workers in standard Prometheus format.
    Suitable for Grafana, Datadog, SIEM, and Dashboard integration.
    """
    content = metrics_collector.generate_prometheus_format()
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")
