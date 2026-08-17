# VulnProof Enterprise Lab

VulnProof는 취약한 기업형 환경을 재현하고, 취약점 발견부터 위험도 평가·안전한 검증·탐지·조치·재검증까지 연결하는 오픈소스 보안 검증 플랫폼입니다.

## 설계 원칙

- 스캐너 실행부와 위험도 판단 로직을 분리합니다.
- Trivy, Grype, Semgrep 등의 결과를 하나의 표준 모델로 정규화합니다.
- EPSS·KEV·자산 중요도 같은 외부 정보는 Enricher로 분리합니다.
- 실제 검증은 명시적으로 허가된 격리 실습 환경에서만 수행합니다.
- CLI에서 시작하되, 나중에 GitHub Actions와 AWS·Kubernetes 환경으로 확장할 수 있게 설계합니다.

자세한 구조는 [`docs/architecture.md`](docs/architecture.md)를 참고하세요.
