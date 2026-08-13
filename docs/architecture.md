# VulnProof 초기 아키텍처

## 목표

VulnProof의 첫 번째 목표는 특정 스캐너의 결과를 그대로 출력하는 것이
아니라, 취약점 발견 결과를 자산 맥락과 결합해 재현 가능한 우선순위와
증거 중심의 보고서로 변환하는 것이다.

## 처리 흐름

```text
입력 대상(image/repository/config)
        │
        ▼
Scanner Adapter
(Trivy, Grype, Semgrep ...)
        │
        ▼
표준 Finding 모델
        │
        ├── Enricher: EPSS, CISA KEV, 노출 정보
        │
        ▼
Risk Scorer
        │
        ▼
ScanReport
        │
        ├── JSON Reporter
        ├── Markdown Reporter
        └── SARIF Reporter
```

## 모듈 책임

### Domain

`models.py`는 Asset, Finding, ScanReport를 정의한다. 외부 도구나 AWS SDK를
직접 import하지 않는다.

### Ports

`ports.py`는 Scanner, Enricher, RiskScorer, Reporter의 계약만 정의한다.
이 계층 덕분에 Trivy를 나중에 Grype로 교체해도 파이프라인을 다시 작성할
필요가 없다.

### Application

`pipeline.py`는 처리 순서만 조정한다. 탐지 명령 실행, API 호출, 파일 출력은
각 어댑터에 맡긴다.

### Adapters

향후 다음 경로에 구현한다.

```text
src/vulnproof/scanners/trivy.py
src/vulnproof/enrichers/epss.py
src/vulnproof/enrichers/kev.py
src/vulnproof/reporters/json_reporter.py
```

## 보안 경계

- 기본 실행은 분석과 보고서 생성만 수행한다.
- 네트워크 요청이나 검증용 실행은 명시적인 옵션과 격리된 실습 환경을 요구한다.
- 실제 기업 자산을 기본 대상으로 삼지 않는다.
- API 키, AWS 자격 증명, 개인키는 소스 코드와 보고서에 저장하지 않는다.

## 구현 순서

1. `models.py`에 대한 단위 테스트
2. Trivy JSON fixture 파서
3. CVSS·자산 중요도 기반 초기 scorer
4. JSON/Markdown reporter
5. Typer CLI
6. EPSS·KEV enricher
7. Docker Compose 기반 취약 실습 환경
8. 안전한 validator와 재검증 흐름
