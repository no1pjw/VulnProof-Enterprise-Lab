# VulnProof 아키텍처

## 문제 정의

기업 보안팀은 많은 스캐너 결과를 받지만, 결과가 실제로 도달·재현 가능한지,
어떤 증거로 확인했는지, 패치 후 사라졌는지를 별도 작업으로 관리하는 경우가
많습니다. VulnProof는 다음 한 줄의 폐쇄 루프를 자동화합니다.

```text
Discover -> Normalize -> Prioritize -> Approve -> Validate -> Evidence -> Remediate -> Retest
```

Nuclei 같은 스캐너나 Atomic Red Team/CALDERA 같은 공격 시뮬레이션 도구를
대체하지 않습니다. 이들의 결과를 받아 **finding 단위 검증과 조치 증명**으로
연결하는 얇고 감사 가능한 계층을 지향합니다.

## 모듈 경계

```text
Trivy JSON                      Asset YAML
    |                               |
    v                               v
ingestors/trivy.py -> Finding -> ContextRiskScorer
                                  |
Playbook YAML -> Policy ----------+
                    |
                    v
              HttpValidator
                    |
                    v
       Evidence ledger + JSON/Markdown
                    |
                    v
          same-playbook Retest
```

- `models.py`: vendor-neutral asset, finding, evidence, validation, retest 모델
- `ingestors/`: 외부 스캐너 포맷을 내부 모델로 변환
- `scoring.py`: 근거 문자열을 함께 남기는 결정론적 점수 계산
- `playbooks.py`: 허용된 동작과 기대 결과를 선언하는 스키마
- `policy.py`: 네트워크 요청 전에 승인·환경·호스트·finding 범위를 검사
- `validator.py`: 크기가 제한된 비파괴 HTTP 관찰과 증거 수집
- `reporting.py`: 기계용 JSON과 리뷰용 Markdown 출력
- `pipeline.py`: 같은 검증을 패치 전후에 실행하는 애플리케이션 흐름

## 신뢰 경계

스캐너 입력과 플레이북은 신뢰하지 않는 입력으로 취급합니다. Pydantic의
`extra="forbid"`로 알 수 없는 필드를 거부하고, 현재 executor는 `GET`과
`HEAD` 이외의 메서드 및 임의 명령을 표현할 수 없게 설계했습니다. 정책 검사는
요청 실행 전에 fail-closed 방식으로 끝나야 합니다.

증거는 응답 원문 전체를 무제한 저장하지 않습니다. 크기를 제한하고 인증·쿠키
헤더를 마스킹하며, 정규화된 데이터의 SHA-256을 계산해 이후 변경 여부를 확인할
수 있게 합니다. 향후에는 본문 secret pattern redaction과 서명된 evidence bundle을
추가할 예정입니다.

## 단계별 확장

1. **MVP (현재)**: Trivy, HTTP playbook, 정책, 증거, 로컬 조치 재검증
2. **Detection proof**: Falco/SIEM 이벤트 correlation ID 수집
3. **More adapters**: Nuclei/Semgrep ingest와 cloud/Kubernetes asset context
4. **CI mode**: 승인된 ephemeral lab에서 검증 후 SARIF/PR 결과 게시
5. **Planner assistance**: AI는 플레이북 초안만 제안하고 schema 검증과 사람 승인을
   통과한 결정론적 executor만 실행

AI가 직접 임의 공격 명령을 생성·실행하는 구조는 범위에 포함하지 않습니다.
