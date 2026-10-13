# LPECO 지속 개발 및 저장소 운영 설계

작성일: 2026-10-12
상태: 사용자 승인, 구현 중

## 1. 목적과 성공 조건

LPECO를 일회성 MVP 브랜치가 아니라 장기간 유지되는 오픈소스 지향 Go
프로젝트로 운영한다. 사람과 개발 에이전트가 같은 규칙을 따르고, 중요한
규칙은 문서 권고에 머물지 않고 로컬 명령과 CI로 검증한다.

이 작업이 완료되면 다음 조건을 만족해야 한다.

- `develop`은 지속 통합 브랜치이고 `main`은 릴리스 가능한 상태만 가진다.
- 기능, 수정, 문서, 테스트, CI 작업의 분기·리뷰·병합·릴리스 절차가 명확하다.
- 기여자가 한 명이어도 동일하게 재현 가능한 로컬 검증 명령이 있다.
- Pull Request에서 포맷, 정적 검사, race test, 빌드, 통합 테스트와 알려진
  Go 취약점 검사가 자동 실행된다.
- 새 probe, candidate rule, adapter 및 report 변경은 LPECO의 읽기 전용
  안전 경계를 약화시키지 못하도록 리뷰 조건과 테스트 조건을 가진다.
- 취약점은 공개 issue가 아닌 비공개 채널로 신고하도록 안내한다.
- 릴리스 버전과 변경 이력이 일관되게 관리된다.
- 아직 없는 원격 저장소나 GitHub 설정은 있는 것처럼 가장하지 않고,
  연결 후 적용할 정확한 설정을 문서화한다.

## 2. 현재 상태와 제약

- 로컬 MVP 이력은 장기 통합 브랜치 `develop`에 있다.
- 원격 저장소는 `https://github.com/goldsimchoi/findlpe.git`이며, 기존
  `main`의 초기 README commit은 변경하지 않고 `develop` 이력에 병합했다.
- 원격 `main`은 릴리스 브랜치로 보존하고, `develop`을 기본 통합 브랜치로
  설정한다.
- Go module은 저장소의 `lpeco/` 하위에 있으며 module path는
  `github.com/normalone/lpeco`다.
- `make verify`와 통합 테스트는 존재하지만 GitHub Actions, 기여 가이드,
  보안 신고 정책, PR 템플릿과 의존성 업데이트 정책은 없다.
- disposable VM 테스트는 이미지와 명시적 guard가 있어야 실행되므로 일반
  호스팅 CI의 필수 check로 만들 수 없다.

이 설계는 module을 저장소 루트로 이동하거나 Go package API를 재구성하지
않는다. 그 작업은 운영 규칙 도입과 별개의 구조 변경이다.

## 3. 브랜치와 병합 모델

### 3.1 장기 브랜치

- `main`: 배포 가능한 릴리스 이력이다. 일반 개발을 직접 수행하지 않는다.
- `develop`: 다음 릴리스를 위한 장기 통합 브랜치다. 현재
  `feature/lpeco-mvp`를 이 이름으로 변경하여 MVP 구현 이력을 보존한다.

두 브랜치 모두 직접 push, force-push와 삭제를 금지한다. 원격 저장소가
생기기 전에는 이 규칙을 문서와 작업 습관으로 적용하고, 원격 연결 후 GitHub
ruleset으로 강제한다.

### 3.2 작업 브랜치

일반 작업은 최신 `develop`에서 시작하며 다음 접두사를 사용한다.

- `feat/<short-description>`: 사용자에게 보이는 기능
- `fix/<short-description>`: 버그 수정
- `docs/<short-description>`: 문서만 변경
- `refactor/<short-description>`: 동작을 바꾸지 않는 구조 개선
- `test/<short-description>`: 테스트와 fixture 개선
- `ci/<short-description>`: 자동화와 빌드 변경
- `chore/<short-description>`: 위 범주에 속하지 않는 유지보수

이름은 소문자 kebab-case로 작성한다. 작업 브랜치는 `develop`으로 PR을
보내고 병합 후 삭제한다. 기능 PR은 squash merge하고 PR 제목을 최종
Conventional Commit 메시지로 사용한다.

### 3.3 릴리스와 긴급 수정

- `release/vX.Y.Z`는 `develop`에서 분기한다.
- release 브랜치에는 버전, changelog, 문서와 릴리스 차단 버그 수정만 넣는다.
- 전체 릴리스 검증 후 `main`에 PR로 병합하고 annotated tag `vX.Y.Z`를 만든다.
- 같은 release commit을 `develop`에 다시 병합하여 릴리스 수정이 빠지지 않게
  한다.
- `hotfix/<short-description>`는 `main`에서 분기하여 `main`에 먼저 병합하고,
  같은 변경을 즉시 `develop`에도 병합한다.

초기 개발 단계는 SemVer `0.y.z`를 사용한다. 첫 공개 후보는 `v0.1.0`이며,
CLI 옵션, JSON report schema, 저장 session schema와 adapter protocol을
프로젝트의 공개 호환성 표면으로 취급한다. 호환성이 깨지는 변경은 0.x
기간에도 changelog와 migration note에 명시한다.

## 4. 저장소 정책 산출물

### 4.1 사람이 읽는 정책

저장소 루트에 다음 파일을 둔다.

- `CONTRIBUTING.md`: 개발 환경, 브랜치, 커밋, PR, 테스트 및 리뷰 규칙
- `SECURITY.md`: 지원 버전, 비공개 취약점 신고, 응답 원칙, 공개 issue 금지
- `CHANGELOG.md`: Keep a Changelog 형식의 `Unreleased`와 버전별 변경 이력
- `docs/development.md`: module 구조, Make target, fixture, CI와 릴리스 절차
- `docs/maintainers/github-settings.md`: 원격 연결 후 ruleset과 repository
  security 설정을 적용하는 체크리스트

라이선스는 프로젝트 소유자의 법적 선택이므로 이 변경에서 임의로 정하지
않는다. 공개 배포 전 별도 결정이 필요한 릴리스 차단 항목으로 문서화한다.

### 4.2 개발 에이전트 정책

`lpeco/AGENTS.md`는 `lpeco/` 아래에서 작업하는 자동화 에이전트에 다음을
강제한다.

- 변경 전 관련 README, safety model, rule catalog와 가까운 테스트를 읽는다.
- source 편집은 작은 단위로 하고 unrelated refactor를 섞지 않는다.
- 새 동작과 bugfix는 테스트를 먼저 추가한다.
- `gofmt`, `go vet`, race test와 필요한 integration test를 완료한다.
- target-side write, exploit, payload delivery, persistence, credential attack,
  service mutation 또는 kernel exploit 추천을 추가하지 않는다.
- evidence가 불완전할 때 안전함이나 exploitability를 단정하지 않는다.
- 실제 비밀이나 고객/assessment 데이터를 fixture와 commit에 넣지 않는다.

`AGENTS.md`는 사람용 `CONTRIBUTING.md`를 대체하지 않는다. 같은 핵심 규칙을
자동화 작업에 맞게 짧고 명령형으로 표현한다.

### 4.3 GitHub 협업 파일

`.github/`에 다음 파일을 둔다.

- `PULL_REQUEST_TEMPLATE.md`: 변경 목적, 안전 영향, 테스트, 문서, 호환성,
  개인정보/비밀값 검토 체크리스트
- `ISSUE_TEMPLATE/bug_report.yml`: 재현 가능한 버그와 redacted diagnostics 수집
- `ISSUE_TEMPLATE/feature_request.yml`: 사용 사례, 안전 영향과 대안 수집
- `ISSUE_TEMPLATE/config.yml`: blank issue를 막고 보안 문제는 `SECURITY.md`로
  안내
- `CODEOWNERS`: repository ownership과 보안 민감 파일의 review routing
- `dependabot.yml`: Go modules와 GitHub Actions를 월 단위로 점검

`CODEOWNERS`는 원격 저장소 소유자인 `@goldsimchoi`를 기본 owner로 사용한다.
단일 maintainer가 자신의 PR을 승인할 수 없으므로 초기 ruleset에서
CODEOWNER approval을 필수로 걸지는 않는다. 두 번째 maintainer가 생기면
필수 승인 1개와 CODEOWNER review를 활성화한다.

## 5. Go 개발 규칙

Go 코드는 Go 공식 formatting과 review 지침을 따른다.

- 모든 Go 파일은 `gofmt` 결과와 같아야 한다.
- package와 exported identifier는 의미 있는 doc comment를 가진다.
- package 이름은 짧고 구체적으로 유지하고 `util`, `common`, `misc` 같은
  의미 없는 bucket package를 만들지 않는다.
- 오류에는 동작에 필요한 context를 추가하되 secret, credential 또는 raw
  target evidence를 노출하지 않는다.
- interface는 실제 consumer가 필요한 최소 surface에서 정의한다.
- dependency 추가는 표준 라이브러리나 기존 dependency로 해결할 수 없는
  이유와 보안/유지보수 영향을 PR에 기록한다.
- generated output, binary와 local session evidence는 commit하지 않는다.

커밋은 Conventional Commits 1.0.0 형식을 사용한다. 허용 type은 `feat`,
`fix`, `docs`, `refactor`, `test`, `ci`, `build`, `chore`, `perf`, `revert`다.
호환성 파괴는 `!`와 `BREAKING CHANGE:` footer로 표시한다. 각 commit은
독립적으로 이해하고 되돌릴 수 있는 하나의 완결된 변경이어야 한다.

## 6. LPECO 안전 기여 규칙

LPECO의 안전 모델은 기능보다 우선한다. 다음은 merge 불가 조건이다.

### 6.1 Probe 변경

새 probe 또는 probe 수정은 반드시 다음을 포함한다.

- registry에 명시된 고유 ID, timeout, output limit, parser와 expected fact type
- `passive-read`, `observable-read`, `temporary-artifact`, `state-changing` 중
  정확한 safety class
- 고정 script와 별도 positional argument 사용; target-derived 값을 script에
  문자열 결합하지 않음
- 정상, 권한 거부, 누락 도구, truncated/partial 또는 malformed 입력 테스트
- target persistent state가 바뀌지 않는 integration evidence

`temporary-artifact`와 `state-changing` probe는 scheduler에서 계속 거부한다.
새 `observable-read` probe는 명시적 opt-in과 실행 전 ID 고지를 요구한다.

### 6.2 Candidate rule 변경

새 rule은 다음 조건을 충족한다.

- 현재 principal과 더 높은 principal/capability boundary를 구분한다.
- control, consumer, trigger와 semantic resolution을 evidence ID로 연결한다.
- 하나의 positive scenario와 서로 다른 원인의 negative scenario 두 개 이상을
  추가한다.
- permission denial, parse error, timeout, truncation 또는 missing tool을
  negative evidence로 사용하지 않는다.
- incomplete evidence를 참조하는 candidate를 P0, high confidence 또는
  `read_only_validated`로 승격하지 않는다.
- exploit step, payload 또는 악용 명령을 report에 생성하지 않는다.

### 6.3 Adapter와 report 변경

- adapter는 공통 contract test를 통과하고 timeout, cancel, output bound,
  malformed response와 transport closure를 다룬다.
- raw transport는 marker/frame 무결성이 확인되지 않으면 성공으로 처리하지
  않는다.
- report schema 또는 error text가 바뀌면 redaction test와 golden/JSON test를
  갱신한다.
- raw evidence body는 기본 terminal/JSON report에 포함하지 않는다.
- session/adapter protocol의 호환성 변경은 migration note와 version 결정을
  동반한다.

## 7. 로컬 검증과 Make target

`lpeco/Makefile`은 사람이 수정하는 명령과 CI가 검사하는 명령을 구분한다.

- `make fmt`: 로컬 Go 파일을 포맷한다.
- `make fmt-check`: 파일을 수정하지 않고 포맷 차이가 있으면 실패한다.
- `make vet`: `go vet ./...`
- `make test`: 일반 unit test
- `make test-race`: race detector를 포함한 전체 일반 test
- `make test-integration`: container 및 cross-adapter integration test
- `make vulncheck`: 고정된 `govulncheck` 버전으로 `./...` 검사
- `make build`: 두 CLI binary를 `bin/`에 빌드
- `make verify`: `fmt-check`, `vet`, `test-race`, `build`, `git diff --check`
- `make verify-ci`: `verify`, `test-integration`, `vulncheck`
- `make test-vm`: 지금처럼 명시적인 disposable VM guard가 있을 때만 실행

CI용 target은 source를 고치지 않는다. `make verify`가 성공한 뒤 tracked
working tree가 바뀌지 않았음을 테스트로 확인한다. 설치형 도구 버전은 Makefile
변수로 고정하여 `@latest`의 비결정성을 피한다.

## 8. CI와 의존성 관리

`.github/workflows/ci.yml`은 `main`과 `develop` 대상 PR 및 두 브랜치 push에서
실행한다. module이 하위 디렉터리에 있으므로 모든 Go 명령은 `lpeco/`를
working directory로 사용한다.

필수 job은 다음과 같다.

1. `quality`: checkout, Go setup, `make verify`
2. `integration`: Linux runner와 Docker로 `make test-integration`
3. `vulnerability`: 고정 버전 `govulncheck ./...`

workflow는 다음 공급망 원칙을 따른다.

- workflow-level `permissions: contents: read`
- PR code에 write token이나 repository secret을 제공하지 않음
- 모든 외부 action을 검증된 full commit SHA로 고정하고 옆에 release tag를
  comment로 기록
- dependency cache는 `lpeco/go.sum`을 기준으로 함
- 동시 실행은 같은 ref의 오래된 run을 취소함
- timeout을 job마다 지정함

Dependabot은 `gomod`와 `github-actions` ecosystem을 월 1회 확인한다. patch와
minor update는 ecosystem별로 묶되 major update는 별도 PR로 만들어 호환성
검토를 강제한다. Dependabot PR도 일반 CI를 모두 통과해야 한다.

`govulncheck` 결과는 호출 가능한 알려진 취약점을 필수 실패로 취급한다.
표준 도구가 informational-only dependency를 보고하면 maintainer가 적용
가능성을 검토하고 결정을 PR 또는 security record에 남긴다.

## 9. PR 및 리뷰 게이트

모든 PR은 다음을 만족해야 한다.

- 목적과 사용자 관점의 동작 변화가 설명되어 있다.
- safety boundary, compatibility와 data exposure 영향이 작성되어 있다.
- 새 동작에는 자동 test가 있고 관련 local command 결과가 기록되어 있다.
- README, safety model, rule catalog, adapter protocol 등 영향받는 문서가
  함께 갱신되어 있다.
- CI의 `quality`, `integration`, `vulnerability`가 성공한다.
- 모든 review conversation이 해결되어 있다.
- secret, 실제 target output, credential와 assessment identifier가 diff에 없다.

원격 저장소 생성 후 `main`과 `develop` ruleset에 PR 필수, 위 세 status check
필수, conversation resolution 필수, force-push/delete 금지, branch up-to-date
필수를 설정한다. admin bypass도 기본 금지한다. 단일 maintainer 단계에서는
승인 수를 0으로 두되 PR self-review checklist와 CI를 생략하지 않는다. 두
번째 maintainer가 생기면 required approval을 1로 올린다.

## 10. 보안 신고와 데이터 처리

`SECURITY.md`는 latest minor release만 보안 수정을 받는다는 초기 지원 정책을
명시한다. 아직 공식 release가 없을 때는 `develop`을 유일한 지원 대상으로
표시한다.

취약점 신고자는 다음 정보를 가능한 범위에서 제공한다.

- 영향받는 version/commit과 platform
- 재현 조건, 영향과 최소 재현 자료
- LPECO가 안전 경계를 넘어 target state를 변경하거나 secret을 노출하는지
- 공개 시점 관련 제약

공개 issue에 exploit detail, credential 또는 실제 assessment evidence를
올리지 않도록 명시한다. 원격 연결 직후 GitHub private vulnerability reporting을
활성화하며, 별도 보안 이메일은 소유자가 실제로 관리할 주소를 제공하기 전에는
문서에 가짜 주소를 넣지 않는다.

## 11. Changelog와 릴리스 검증

`CHANGELOG.md`는 `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security` 범주를 사용한다. 사용자에게 보이는 모든 PR은 `Unreleased`를
갱신한다. release 브랜치에서 해당 내용을 버전과 날짜 아래로 이동한다.

릴리스 전에는 다음 증거가 필요하다.

- clean checkout에서 `make verify-ci` 성공
- 준비된 disposable image에서 `make test-vm` 성공
- README의 열 가지 acceptance condition 확인
- 지원하는 Linux fixture 결과 확인
- changelog, version, migration note와 보안 지원 범위 확인
- binary가 version metadata와 source commit을 보고하는지 확인
- license 결정 및 repository 공개 설정 확인

현재 CLI에는 version metadata 기능이 없으므로 첫 공개 릴리스 전 별도 기능
작업으로 추가한다. 이 운영 규칙 변경 자체는 release binary를 발행하지 않는다.

## 12. 실패 처리와 현실적인 경계

- CI가 Docker 또는 외부 vulnerability database 장애로 실패하면 실패를
  무시하지 않고 재실행하여 일시 장애인지 확인한다.
- `govulncheck`를 실행할 수 없는 환경은 성공으로 간주하지 않는다.
- VM image가 없는 일반 CI는 VM test를 `skipped`로 위장하지 않는다. VM
  검증은 별도 release evidence로 기록한다.
- ruleset, private vulnerability reporting와 default branch 변경은 실제
  GitHub API readback 전에는 완료되었다고 주장하지 않는다.
- license 또는 보안 연락처가 정해지지 않은 상태에서 가짜 식별자나 연락처를
  만들지 않는다.

## 13. 구현 순서

1. 현재 브랜치를 `develop`으로 변경하고 상태를 검증한다.
2. 기여·보안·개발·maintainer·changelog 문서를 추가한다.
3. module-scoped `AGENTS.md`, PR 및 issue template, CODEOWNERS와 Dependabot
   설정을 추가한다.
4. Makefile에 비변경 format check, vulnerability scan과 CI aggregate target을
   추가하고 먼저 검증 테스트를 작성한다.
5. 최소 권한과 SHA pinning을 적용한 GitHub Actions CI를 추가한다.
6. 문서의 명령과 자동화가 실제로 일치하는지 검사한다.
7. `make verify`, `make test-integration`, `make vulncheck`를 실행하고 tracked
   tree가 깨끗한지 확인한다.
8. 변경을 Conventional Commit 단위로 commit한다.

브랜치 이름 변경은 commit이 아니므로 구현 결과에서 현재 branch와 commit
graph를 별도로 증거로 제시한다.

## 14. 근거 자료

- Go Code Review Comments: <https://go.dev/wiki/CodeReviewComments>
- Go govulncheck tutorial: <https://go.dev/doc/tutorial/govulncheck>
- Go module release workflow: <https://go.dev/doc/modules/release-workflow>
- GitHub protected branches: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches>
- GitHub Go CI guide: <https://docs.github.com/en/actions/tutorials/build-and-test-code/go>
- GitHub Actions secure use: <https://docs.github.com/en/actions/reference/security/secure-use>
- GitHub security policy: <https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/add-security-policy>
- Conventional Commits 1.0.0: <https://www.conventionalcommits.org/en/v1.0.0/>
- Semantic Versioning 2.0.0: <https://semver.org/>

## 15. 수용 기준

- 현재 branch가 정확히 `develop`이다.
- `main`과 `develop`의 역할 및 모든 작업 branch 규칙이 문서화되어 있다.
- 기여, 보안, 개발, maintainer, changelog 및 agent 규칙 파일이 존재하고 서로
  모순되지 않는다.
- PR/issue template, CODEOWNERS와 Dependabot 설정이 syntax-valid하다.
- CI workflow가 syntax-valid하고 least privilege, full-SHA action pinning,
  timeout과 concurrency를 가진다.
- `make verify-ci`가 성공한다.
- `make verify`는 tracked source를 변경하지 않는다.
- 기존 열 가지 acceptance test와 integration suite가 계속 성공한다.
- `govulncheck`가 호출 가능한 알려진 취약점을 보고하지 않는다.
- 원격에서만 가능한 설정과 VM 검증은 완료 여부를 과장하지 않고 명확한
  후속 체크리스트로 남는다.
