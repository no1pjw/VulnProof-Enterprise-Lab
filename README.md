# VulnProof Enterprise Lab

VulnProof는 **스캐너가 발견한 후보 취약점이 실제 자산에서 재현되는지 안전하게
검증하고, 조치 전후의 증거를 남기는 보안 검증 자동화 프로젝트**입니다.

단순히 Trivy/Nuclei/Semgrep 결과를 다시 보여주는 도구가 아닙니다. 발견 결과를
공통 모델로 정규화한 뒤 자산 맥락을 반영해 우선순위를 계산하고, 사람이 검토할
수 있는 YAML 플레이북으로 비파괴 검증을 수행합니다. 모든 능동 검증은 명시적
승인, 자산 허용 목록, 실습 환경 정책을 통과해야 합니다.

## 현재 MVP

- Trivy JSON을 공통 `Finding` 모델로 변환
- CVSS, 자산 중요도, 외부 노출 여부를 이용한 설명 가능한 위험 점수
- YAML 기반 HTTP 검증 플레이북 (`GET`/`HEAD`만 지원)
- `--approve`, 환경, 호스트 allowlist를 검사하는 fail-closed 정책
- 응답 크기와 시간을 제한한 검증 및 민감 헤더 마스킹
- SHA-256 증거 원장과 JSON/Markdown 보고서
- 동일 플레이북으로 취약 버전과 조치 버전을 비교하는 remediation retest
- 로컬에서만 열리는 Docker Compose 데모 환경

> 이 저장소의 `VP-LAB-0001`은 흐름을 재현하기 위한 합성 시나리오입니다.
> 실제 제품 취약점이나 CVE를 사칭하지 않습니다. 소유하거나 명시적으로 허가받은
> 환경에서만 사용하세요.

## 5분 데모

Python 3.10 이상과 Docker Compose가 필요합니다.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

vulnproof ingest fixtures/trivy-demo.json \
  --asset config/assets/demo-api.yaml \
  --output reports/scan.json

docker compose -f lab/docker-compose.yml up -d --build

vulnproof retest reports/scan.json \
  --finding VP-LAB-0001 \
  --playbook playbooks/VP-LAB-0001.yaml \
  --asset config/assets/demo-api.yaml \
  --before-target http://127.0.0.1:18080 \
  --after-target http://127.0.0.1:18081 \
  --approve \
  --output reports/retest.json

docker compose -f lab/docker-compose.yml down
```

Docker Compose가 없는 개발 환경에서는 동일한 fixture를 로컬 프로세스로 실행할
수 있습니다.

```bash
./scripts/run-local-demo.sh
```

성공하면 취약 fixture는 `confirmed`, 조치 fixture는 `not_confirmed`, 최종 조치
판정은 `remediation_verified: true`가 됩니다. 사람이 읽을 보고서는
`reports/retest.md`에 함께 생성됩니다.

## 안전 장치

- `validation_enabled: true`인 자산만 능동 검증
- 플레이북에 허용된 환경과 자산의 `allowed_hosts`를 모두 확인
- 플레이북과 finding ID가 일치해야 실행
- 사용자 승인 없이는 네트워크 요청을 보내지 않음
- 파괴적 플레이북 거부, 임의 셸 명령 실행 기능 없음
- URL 내 자격 증명 거부, 응답의 인증·쿠키 헤더 마스킹
- 최대 timeout 15초, 응답 증거 최대 16KiB

설계와 확장 계획은 [docs/architecture.md](docs/architecture.md)를 참고하세요.

## 개발

```bash
pytest
ruff check .
```

## License

라이선스 파일은 정식 공개 범위를 결정한 뒤 추가할 예정입니다.
