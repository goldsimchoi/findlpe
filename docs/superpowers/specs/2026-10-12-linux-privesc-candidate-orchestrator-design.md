# Linux 권한상승 후보 오케스트레이터 설계

작성일: 2026-10-12
상태: 대화상 설계 승인, 구현 전 사용자 명세 검토 대기

작업명과 CLI binary 이름은 **`lpeco`**(Linux Privilege Escalation Candidate Orchestrator)로 고정한다. 구현 소스는 workspace의 `lpeco/` 하위에 둔다.

## 1. 목적

이 프로젝트는 승인된 레드팀 및 침투 테스트에서 초기 Linux 저권한 셸을 확보한 뒤, 권한상승 가능성이 있는 프로세스·서비스·실행 체인을 자동으로 조사하는 운영자 측 도구다.

도구의 첫 번째 목표는 익스플로잇을 실행하는 것이 아니다. SSH, reverse/raw shell 또는 C2 세션을 통해 읽기 전용 증거를 수집하고, 현재 사용자가 영향을 줄 수 있는 객체와 더 높은 권한으로 실행되는 소비자를 연결하여 검토 가치가 있는 후보를 우선순위와 함께 제시한다.

성공한 실행은 다음 질문에 답해야 한다.

- 현재 사용자는 누구이며 어떤 그룹, capability, namespace와 mount 제약 안에 있는가?
- 어떤 프로세스와 서비스가 현재 사용자보다 높은 권한으로 실행되는가?
- 그 실행 주체가 어떤 unit, 트리거, 실행 파일, 스크립트, 설정 및 환경 파일에 의존하는가?
- 현재 사용자가 그 의존 객체나 경로 구성 요소를 실제로 제어할 수 있는가?
- 자동 또는 현실적인 재실행 경로가 존재하는가?
- 어떤 사실이 확인됐고, 무엇이 권한 거부나 세션 한계 때문에 확인되지 않았는가?

## 2. 범위

### 2.1 MVP 포함 범위

- Linux 타깃
- 운영자 머신에서 실행하는 Go 단일 바이너리
- SSH, raw reverse shell listener, stdin/stdout bridge
- 프로세스와 systemd 중심의 우선 조사
- cron 및 SysV init 기본 조사와 비-systemd fallback
- sudo 정책 단서, SUID/SGID, file capability, 커스텀 바이너리, 실행 체인 및 컨테이너 관리 표면의 후순위 조사
- 사실 기반 그래프와 검증 규칙을 이용한 P0/P1/P2 후보 생성
- 사람용 터미널 보고서와 JSON 보고서
- 중단 후 재개 가능한 로컬 세션 기록
- 외부 프로세스 기반 JSON-RPC/JSONL 어댑터 규격과 C2 스타일 예제 어댑터

### 2.2 MVP 제외 범위

- 실제 권한상승 또는 익스플로잇 실행
- 서비스 시작, 중지, 재시작 또는 `daemon-reload`
- 파일 생성·수정·삭제, 권한 변경 및 임시 파일을 이용한 쓰기 검증
- 비밀번호 대입, 사용자 전환, sudo를 통한 명령 실행 또는 비밀번호 제출
- 광범위한 자격증명·비밀값 검색
- 네트워크 탐색과 포트 스캔
- 커널 익스플로잇 추천 및 자동 CVE 공격
- 타깃 센서나 바이너리 업로드
- 특정 상용·오픈소스 C2 제품에 대한 직접 통합
- Windows 및 macOS
- 완전한 다단계 자동 공격 경로 탐색

업로드·다운로드와 타깃 센서는 향후 프로토콜 확장 지점으로만 예약한다. MVP 실행은 agentless이며 타깃 파일시스템에 산출물을 남기지 않는다.

## 3. 기존 도구에서 가져올 교훈과 차별점

- [PEASS-ng](https://github.com/peass-ng/PEASS-ng)는 넓은 정적 열거 범위를 제공한다.
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)은 중요도와 세부 수준을 나누고 정적 검사와 프로세스 관찰을 함께 수행한다.
- [pspy](https://github.com/DominicBreuker/pspy)는 비특권 상태에서 `/proc` 스캔과 inotify를 결합해 짧은 프로세스를 관찰한다.
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)는 검사 ID, 위험 수준, 구조화된 보고가 유용함을 보여준다.
- [Seatbelt](https://github.com/GhostPack/Seatbelt)는 수집 모듈을 독립적으로 구성하는 사례를 제공한다.

MVP의 차별점은 더 많은 텍스트를 출력하는 것이 아니라 다음에 있다.

1. 세션 종류와 타깃 능력에 맞춰 조사를 조정한다.
2. 프로세스, 서비스, 트리거, 실행 의존성과 유효 권한을 하나의 증거 그래프로 연결한다.
3. 실패나 미수집을 안전함으로 오인하지 않는다.
4. 후보마다 원시 근거, 확인 수준과 누락된 사실을 함께 제시한다.
5. systemd의 병합 및 실행 의미를 단순 문자열 검색이 아니라 구조적으로 해석한다.

## 4. 핵심 원칙

### 4.1 운영자 측 분석

타깃은 최소한의 읽기 전용 명령만 실행한다. 정규화, 그래프 구성, 규칙 평가, 보고서 생성과 세션 저장은 운영자 머신에서 수행한다. 타깃에 Python, JSON 도구 또는 별도 런타임을 요구하지 않는다.

### 4.2 transport와 조사 의도의 분리

systemd 또는 프로세스 수집기는 SSH 명령을 직접 전송하지 않는다. 수집기는 필요한 fact와 probe를 선언하고, 세션 어댑터 및 planner가 현재 채널에 맞는 실행 변형을 선택한다.

### 4.3 증거 우선

모든 fact와 그래프 edge는 하나 이상의 evidence ID를 가져야 한다. 후보는 관련 증거와 누락 사실을 모두 참조해야 한다. 원시 출력은 parser 오류가 나더라도 보존한다.

### 4.4 보수적 판정

권한 거부, 잘린 출력, 알 수 없는 ACL이나 해석하지 못한 systemd specifier는 음성 증거가 아니다. 불확실성은 후보의 우선순위 또는 confidence를 낮추고 `missing_facts`에 기록한다.

### 4.5 읽기 전용 기본값

MVP 자동 스캔은 타깃의 지속 상태를 바꾸는 명령을 실행하지 않는다. 서비스 제어, 쓰기 기반 권한 확인, 인증 시도와 익스플로잇 검증은 제공하지 않는다.

여기서 읽기 전용은 도구가 애플리케이션·설정·서비스 상태를 의도적으로 변경하지 않는다는 뜻이다. 운영체제가 read access time, audit 또는 보안 로그를 기록할 가능성까지 없음을 보장하지는 않으며, 보고서에 이 한계를 명시한다.

## 5. 전체 아키텍처

```text
Session Adapter
      |
Capability Profiler
      |
Adaptive Probe Planner
      |
Collectors -> Normalizer -> Evidence Store
                              |
                       Privilege Graph
                              |
                    Validation Rule Engine
                              |
                       Ranked Reporter
```

### 5.1 Session Adapter

전송 채널의 연결, 명령 실행, timeout, 취소 및 결과 프레이밍을 담당한다. 도메인 분석과 candidate 규칙을 포함하지 않는다.

내장 어댑터:

- `ssh`: 종료 코드와 stdout/stderr를 분리할 수 있는 SSH 실행
- `raw-listen`: 도구가 직접 한 개의 reverse/raw shell 연결을 수락
- `stdio-bridge`: stdin/stdout을 셸 또는 외부 래퍼와 연결

외부 어댑터는 별도 프로세스로 실행하고 JSON-RPC 요청과 JSONL 이벤트를 stdio로 교환한다. Go의 동적 plugin ABI는 사용하지 않는다.

### 5.2 Capability Profiler

다음 세션 및 호스트 능력을 최소 probe로 판별한다.

- TTY 및 대화형 여부
- 셸 종류와 POSIX 호환성
- 종료 코드 및 stdout/stderr 분리 가능 여부
- 동시 또는 비동기 실행 가능 여부
- 명령 및 출력 크기 제한
- 연결 안정성과 cancel 지원
- 운영체제, 아키텍처, init 및 systemd 실행 여부
- `/proc`, cgroup, unit 파일과 D-Bus 질의 접근성
- `systemctl`, `stat`, `readlink`, `getfacl`, `getcap` 등 선택 기능

능력 탐지는 privilege 후보를 만들지 않으며 planner가 사용할 profile만 생성한다.

### 5.3 Adaptive Probe Planner

probe의 요구 기능과 안전 등급을 capability profile에 대조해 실행 가능한 변형을 선택한다. 전체 명령 목록을 무조건 실행하지 않고, 먼저 고권한 소비자를 찾은 뒤 관련 경로와 권한만 확장 조사한다.

planner는 다음을 보장한다.

- 동일 세션에서 완료된 probe를 불필요하게 반복하지 않는다.
- 실패한 probe의 대체 변형이 있을 때만 fallback을 실행한다.
- 경로와 같은 타깃 유래 값을 셸 문자열에 직접 삽입하지 않는다.
- raw shell에서는 probe를 직렬화하고, 비동기 실행이 보장되는 adapter에서만 제한적으로 병렬화한다.

### 5.4 Collectors

collector는 한 가지 영역의 원시 결과를 fact로 바꾸는 데 집중한다.

- identity 및 execution context
- process 및 cgroup
- systemd unit과 activation
- cron 및 SysV init
- path, ownership, mode, ACL, symlink와 mount
- sudo policy 단서
- SUID/SGID 및 file capability
- executable, interpreter, library 및 plugin dependency
- container 및 관리 socket

### 5.5 Normalizer와 Evidence Store

adapter별 출력을 공통 fact schema로 변환한다. 로컬 세션 디렉터리는 다음 구조를 사용한다.

```text
session.json
facts.jsonl
evidence/<probe-id>.txt
candidates.json
```

각 evidence에는 SHA-256, probe ID, 수집 시각, adapter, 명령 변형 ID, 완료 상태, 종료 상태와 truncation 여부가 포함된다. 세션 디렉터리와 파일 권한은 기본적으로 소유자 전용으로 설정한다.

기본 세션 저장 위치는 `${XDG_STATE_HOME}/lpeco/sessions/<session-id>`이며, `XDG_STATE_HOME`이 없으면 현재 사용자의 `.local/state/lpeco/sessions/<session-id>`를 사용한다. `--state-dir`로 명시적인 위치를 지정할 수 있다.

### 5.6 Privilege Graph

MVP는 외부 그래프 데이터베이스 없이 메모리 그래프를 구성하고 JSON으로 내보낸다.

주요 node 유형:

- `Principal`: UID, GID, group 또는 capability 주체
- `Process`: 실행 중이거나 관찰된 프로세스
- `Unit`: systemd service 및 관련 unit
- `Trigger`: timer, socket, path, cron 또는 재시작 조건
- `File`, `Directory`, `Executable`, `Script`, `Library`
- `Socket`, `Mount`, `Namespace`, `Container`

주요 edge 유형:

- `RUNS_AS`, `SPAWNED_BY`, `MANAGED_BY`
- `ACTIVATES`, `EXECUTES`, `INTERPRETS`, `LOADS`
- `READS_CONFIG`, `READS_ENVIRONMENT`
- `CAN_WRITE`, `CAN_EXECUTE`, `CAN_TRAVERSE`
- `RESOLVES_THROUGH`, `LOCATED_ON`

node와 edge는 안정적인 ID, source collector, evidence reference와 confidence를 가진다.

### 5.7 Validation Rule Engine

규칙은 graph pattern을 찾은 뒤 추가 fact가 필요한지 판단한다. 규칙 본문은 MVP에서 typed Go 코드로 구현하고, ID, 설명, 범주와 심각도 같은 metadata만 선언적으로 둔다. 범용 규칙 DSL은 만들지 않는다.

### 5.8 Reporter

터미널 출력은 후보를 우선순위순으로 표시하고 기본적으로 민감값을 마스킹한다. JSON 출력은 자동 처리에 필요한 구조화된 fact, candidate와 evidence reference를 포함하되, 원시 evidence 본문은 별도 파일로 유지한다.

## 6. 데이터 흐름

1. 사용자가 adapter와 세션 옵션으로 스캔을 시작한다.
2. adapter가 handshake를 완료하고 capability profile을 만든다.
3. identity, namespace, mount 및 init 컨텍스트를 수집한다.
4. 프로세스와 systemd를 우선 조사해 고권한 소비자와 활성화 경로를 찾는다.
5. 발견된 소비자가 참조하는 실행 파일, 스크립트, 환경·설정 파일과 각 상위 디렉터리만 확장 조사한다.
6. path collector가 mode, 소유권, ACL, symlink, mount read-only 상태를 반영한 유효 제어 가능성을 계산한다.
7. 규칙 엔진이 그래프에서 후보를 생성하고 필요한 read-only 확인 probe를 planner에 요청한다.
8. 강한 프로세스·서비스 후보가 부족하면 sudo, SUID/SGID, file capability, 커스텀 바이너리와 컨테이너 표면을 조사한다.
9. 후보를 재평가해 P0/P1/P2와 별도의 confidence를 부여한다.
10. 터미널 및 JSON 보고서를 생성하고 세션 checkpoint를 기록한다.

## 7. 후보 생성과 우선순위

priority와 confidence는 분리한다. priority는 운영자가 먼저 볼 순서를, confidence는 수집 근거의 완전성을 뜻한다.

- **P0 — 연결된 경로:** 고권한 소비자, 현재 사용자가 제어 가능한 객체, 도달 가능한 재실행·reload·activation 근거가 모두 있다.
- **P1 — 강한 후보:** 소비자와 제어 지점이 확인됐지만 trigger, 완화 설정 또는 경로 의미 중 하나가 불명확하다.
- **P2 — 조사 후보:** 특이한 고권한 서비스나 바이너리가 있으나 현재 사용자의 제어 가능성이 확인되지 않았다.

P0는 익스플로잇 성공을 보장하거나 실제 권한상승을 확인했다는 의미가 아니다. UI에서는 `confirmed exploit`이라는 표현을 사용하지 않는다.

candidate schema의 필수 필드:

```text
id
rule_id
category
priority
confidence
current_principal
target_principal
privileged_consumer
controlled_object
trigger
path_nodes[]
evidence_ids[]
missing_facts[]
validation_status
summary
```

`validation_status`는 `unvalidated`, `read_only_validated`, `incomplete` 중 하나다.

confidence는 `high`, `medium`, `low` 중 하나다. 모든 필수 edge가 직접 evidence를 가지면 `high`, 한 가지 의미 또는 수집 제약이 남으면 `medium`, 둘 이상이 남으면 `low`다. `low` 후보는 P0가 될 수 없다.

### 7.1 초기 candidate 규칙

MVP 규칙 집합은 다음으로 제한한다.

- `systemd.writable-unit-source`: 더 높은 권한의 system unit에 실제 적용되는 fragment 또는 drop-in이 현재 principal에 의해 쓰기 또는 교체 가능하다.
- `systemd.writable-exec-chain`: 더 높은 권한의 unit이 사용하는 `Exec*` executable, interpreter 또는 script가 쓰기 또는 교체 가능하다.
- `systemd.controlled-environment`: 쓰기 가능한 `EnvironmentFile` 값이 executable 검색, interpreter, library 또는 plugin 경로에 실제로 사용된다. 단순히 environment 파일이 writable하다는 이유만으로 P0를 만들지 않는다.
- `systemd.controlled-search-path`: simple executable name을 쓰는 고권한 unit의 유효 `ExecSearchPath` 또는 `PATH`에서 먼저 선택되는 디렉터리를 현재 principal이 제어한다.
- `process.replaceable-dependency`: 관찰된 고권한 process의 executable, interpreter, script 또는 확인된 loader/plugin dependency가 교체 가능하다. 재사용 가능한 trigger나 reload 관계가 없으면 최대 P1이다.
- `scheduler.writable-command`: cron 또는 SysV 실행 체인의 command, interpreter나 script가 제어 가능하고 고권한 실행 일정이 확인된다.
- `binary.suid-sgid-control`: SUID/SGID 실행 파일 또는 그 해석 체인이 제어 가능하다. mount와 파일 변경 시 privilege bit 보존 여부가 불명확하면 P1 이하로 제한한다.
- `binary.capability-boundary`: 실행 파일 capability가 현재 principal보다 높은 보안 경계를 제공하며, 파일 또는 실행 의존성을 제어할 수 있다. capability 존재만으로는 P2 inventory다.
- `binary.loader-path-control`: 고권한 실행 파일의 확인된 loader 또는 plugin 검색 경로에 현재 principal이 제어하는 디렉터리가 있고 재실행 경로가 있다.
- `delegation.sudo-policy`: 읽기 가능한 정책 또는 opt-in 조회에서 현재 principal이 더 높은 principal로 특정 명령을 실행할 수 있음이 확인된다. MVP는 해당 명령의 악용법을 생성하거나 실행하지 않는다.
- `container.admin-socket-control`: 더 높은 권한의 daemon에 연결된 관리 socket에 현재 principal이 쓰기 가능하다. 알려진 그룹 이름만으로는 후보를 만들지 않는다.

규칙은 현재 principal보다 높은 `target_principal`이 없으면 privilege-escalation 후보를 만들지 않는다. 같은 사용자로 실행되는 user service와 같은 항목은 inventory에만 남긴다.

## 8. 수집 상세

### 8.1 Identity와 실행 컨텍스트

- real/effective/saved UID와 GID를 확인 가능한 범위에서 수집
- 보조 그룹
- 현재 프로세스 capability 집합
- user, PID, mount 및 기타 관련 namespace 식별자
- 컨테이너 단서와 host 경계
- SELinux/AppArmor 및 `NoNewPrivileges` 등 조회로 확인 가능한 완화 상태

### 8.2 프로세스

`/proc`를 우선 데이터 소스로 사용한다. 접근 가능한 범위에서 다음을 수집한다.

- PID, PPID, UID/GID, capability와 상태
- cmdline, executable, cwd, root, cgroup
- 고권한 프로세스가 참조하는 path 중심의 열린 파일 및 memory map metadata
- 프로세스와 systemd unit의 cgroup 관계
- 현재 사용자보다 높은 UID/GID 경계 또는 현재 세션에 없는 effective capability를 가진 프로세스

전체 environment는 수집하지 않는다. 접근 가능한 경우에도 실행 경로 해석에 필요한 `PATH`, `LD_LIBRARY_PATH`, `LD_PRELOAD`, 언어별 module path와 같은 allowlist key만 수집하며 보고서에서는 기본 마스킹한다.

짧은 프로세스는 설정 가능한 관찰 시간 동안 반복 `/proc` snapshot으로 찾는다. MVP 기본 관찰 시간은 30초이고 `--observe`로 조정하거나 0으로 비활성화할 수 있다. 이 방식의 관찰 한계를 결과에 명시한다.

### 8.3 systemd

systemd는 독립적인 최우선 collector다. 실행 중인 service만 보지 않고 다음을 연결한다.

- system 및 user manager의 loaded, inactive, failed, oneshot unit
- service와 timer, socket, path activation 관계
- main unit fragment, template/instance, alias와 drop-in
- `/etc`, `/run`, `/usr/lib`, `/lib` 계열의 실제 precedence
- `ExecCondition`, `ExecStartPre`, `ExecStart`, `ExecStartPost`, `ExecReload`, `ExecStop`, `ExecStopPost`
- `User`, `Group`, `DynamicUser`, capability, `NoNewPrivileges`와 filesystem 격리 설정
- `EnvironmentFile`, `WorkingDirectory`, `RootDirectory`, `RootImage`, `ExecSearchPath`
- process PID/cgroup과 unit의 관계
- restart 정책과 activation timing

`systemctl`이 존재하고 조회가 성공하면 `systemctl show`로 manager가 알고 있는 effective runtime property를 수집하고, `systemctl cat` 및 unit 파일 파싱으로 provenance를 연결한다. D-Bus 또는 `systemctl` 접근이 불가능하면 파일 기반 parser로 fallback하되 결과를 `partial`로 표시한다.

systemd 명령줄은 일반 셸 명령으로 간주하지 않는다. systemd quoting, prefix, specifier와 환경 치환 규칙을 별도 parser로 처리한다. 해석에 필요한 instance 또는 manager context가 없으면 추정하지 않고 missing fact로 남긴다.

drop-in 병합은 [systemd unit 규칙](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)을 따르고, 각 `Exec*` 단계는 [systemd service 규칙](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)에 따라 별도 실행 edge를 만든다. timer와 service 연결은 [systemd timer 규칙](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)을 따른다.

### 8.4 경로와 유효 제어 가능성

파일 존재 여부나 단순 mode bit 하나만으로 후보를 만들지 않는다.

- 모든 symlink를 단계별로 해석하고 loop 및 race 가능성을 기록
- 파일과 각 상위 디렉터리의 소유권, mode 및 traverse/write 권한 확인
- `getfacl`이 있으면 POSIX ACL을 포함하고, 없는데 ACL 가능성이 배제되지 않으면 confidence를 낮춤
- `/proc/self/mountinfo`를 이용해 read-only 및 `noexec`, `nosuid` 같은 관련 mount 상태 반영
- 현재 UID/GID와 보조 그룹 기준으로 권한 계산
- 쓰기 동작으로 권한을 시험하지 않음

mount flag는 실행 의미와 함께 평가한다. 예를 들어 `noexec`는 파일을 interpreter가 읽는 경로까지 자동으로 차단한다고 가정하지 않는다.

### 8.5 후순위 바이너리 및 위임 표면

기본 실행은 프로세스와 서비스 단계를 먼저 완료한다. 그 결과 P0와 P1이 모두 0개이면 다음 후순위 조사를 자동 실행한다. `--full`을 지정하면 앞 단계 결과와 관계없이 후순위 조사도 실행한다.

- readable 정책 파일에서 얻는 sudo 단서
- opt-in `observable-read` 모드에서만 비대화형 정책 조회; 비밀번호는 제공하거나 요청하지 않음
- SUID/SGID 실행 파일과 mount의 `nosuid` 상태
- file capability
- 배포판 패키지 소유 여부를 확인 가능한 커스텀·비패키지 실행 파일
- 실행 파일이 참조하는 interpreter, script, library 및 plugin path
- writable container-management socket 및 그 socket에 대한 현재 principal의 실제 접근권한

filesystem 전체 검색은 `/proc`, `/sys`, `/dev`, runtime pseudo-filesystem과 원격 mount를 기본 제외하고, 각 local mount를 한 번만 방문한다. 사용자는 scan root와 제외 path를 추가 지정할 수 있다.

커널 버전은 환경 metadata로만 보존한다. MVP는 kernel CVE 후보나 exploit을 추천하지 않는다.

## 9. Probe 모델과 안전 정책

probe 정의의 필수 필드:

```text
id
collector
safety_class
requirements
variants[]
timeout
max_output
parser
produces[]
redaction_policy
```

안전 등급:

- `passive-read`: 파일, procfs 또는 조회 전용 인터페이스 읽기
- `observable-read`: 지속 상태는 바꾸지 않지만 감사 로그나 보안 제품에 관측될 수 있는 정책 질의
- `temporary-artifact`: MVP에서 실행 금지
- `state-changing`: MVP에서 실행 금지

기본 스캔은 `passive-read`만 자동 실행한다. `observable-read`는 명시적 CLI opt-in이 있어야 하며, 실행 전 대상 probe ID를 보여준다. `temporary-artifact`와 `state-changing`은 MVP scheduler가 거부한다.

고정 명령 template만 probe registry에 등록할 수 있다. 타깃에서 얻은 path나 identifier를 후속 probe에 전달할 때는 adapter가 지원하는 안전한 인자 encoding을 사용하며, 명령 문자열 연결은 허용하지 않는다.

## 10. Adapter와 외부 plugin 프로토콜

### 10.1 공통 기능

adapter handshake는 다음 capability를 반환한다.

```text
protocol_version
transport_kind
interactive
tty
reliable_exit_status
separate_stderr
async_tasks
cancel
max_command_bytes
max_output_bytes
upload
download
```

MVP RPC method:

- `handshake`
- `open_session`
- `exec`
- `poll`
- `cancel`
- `close_session`

`upload`과 `download` method name은 향후 버전을 위해 예약하지만 MVP core는 호출하지 않는다.

### 10.2 raw shell framing

각 실행은 예측 불가능한 nonce를 포함한 시작 및 종료 marker로 감싼다. parser는 prompt, banner와 echo를 marker 밖의 transport noise로 분리한다. stderr가 분리되지 않으면 `merged_output=true`로 기록한다.

raw shell adapter는 동시에 하나의 probe만 실행한다. 종료 marker가 없으면 성공으로 간주하지 않고 `timeout`, `truncated` 또는 `partial`로 종료한다. 임의의 기존 터미널 세션을 강제로 가져오는 기능은 제공하지 않으며, 셸 연결을 도구의 listener 또는 bridge를 통해 시작해야 한다.

listener는 bind 주소를 반드시 명시하게 하고 한 번에 한 연결만 받는다. wildcard 주소 bind는 `--allow-public-bind`가 함께 지정되지 않으면 거부하며, 대기 timeout 이후 자동 종료한다. listener는 reverse-shell payload를 생성하지 않는다.

### 10.3 SSH

SSH adapter는 기존 ssh-agent와 명시적으로 제공된 key를 우선 사용한다. 비밀번호가 필요하면 대화형 입력으로만 받고 세션 파일에 저장하지 않는다. host key 검증을 기본으로 하며, 검증 비활성화는 사용자가 명시적으로 선택해야 한다.

### 10.4 C2 스타일 예제 adapter

MVP는 특정 C2 API에 종속되지 않는 참조 adapter를 제공한다. 이 adapter는 JSON-RPC 요청을 비동기 task ID로 변환하고 fixture backend를 통해 poll/cancel 동작을 시연한다. 실제 C2 통합은 동일 contract를 구현하는 별도 plugin으로 추가한다.

## 11. 오류 처리와 재개

모든 probe 결과는 다음 상태 중 하나를 가진다.

```text
complete | partial | unavailable | timeout | truncated | parse_error
```

- 명령 부재와 권한 거부는 `unavailable` 또는 `partial` evidence로 기록한다.
- parser가 실패해도 원시 evidence는 보존한다.
- 읽기 전용이며 idempotent인 probe만 최대 한 번 자동 재시도한다.
- session disconnect 시 진행 중 probe는 성공으로 기록하지 않는다.
- 재접속하면 마지막 완료 checkpoint 이후부터 재개한다.
- retry나 resume로 동일 evidence가 들어오면 session ID, probe ID와 input fingerprint로 중복 제거한다.
- output limit을 넘으면 앞부분만으로 정상 판정하지 않고 `truncated`로 표시해 대체 probe 또는 범위 축소를 시도한다.
- adapter/plugin crash는 core를 종료시키지 않고 해당 세션을 중단 가능 상태로 남긴다.

## 12. 개인정보와 민감 데이터

프로세스 인자와 설정 경로에는 토큰이나 비밀번호가 포함될 수 있다.

- 터미널 보고서는 알려진 민감 패턴의 값을 기본 마스킹한다.
- 전체 원시 evidence는 운영자 로컬에만 저장하고 소유자 전용 권한을 적용한다.
- JSON candidate 보고서는 기본적으로 원시 비밀값을 복제하지 않고 evidence ID만 참조한다.
- 향후 명시적 raw export가 추가되더라도 별도 opt-in으로 취급한다.

## 13. CLI 경험

명령 구조의 목표 형태:

```text
lpeco scan ssh <target>
lpeco listen raw --bind <address>
lpeco scan bridge --adapter <plugin-command>
lpeco resume <session-id>
lpeco report <session-id> --format terminal|json
```

기본 scan은 passive read, process/systemd 우선, 30초 관찰과 후보 중심 보고를 사용한다. 상세 raw inventory는 별도 verbose 옵션에서만 표시한다.

## 14. 테스트 전략

### 14.1 Parser golden tests

- 배포판과 systemd 버전별 unit/show 출력
- BusyBox 및 최소 사용자 공간 출력
- locale 차이, 공백, quoting, symlink와 잘린 출력
- 권한 거부 및 사라지는 `/proc/<pid>` race

### 14.2 Candidate rule tests

각 규칙은 positive fixture와 최소 두 개의 negative fixture를 가진다. 특히 다음 오탐을 방지한다.

- 같은 사용자로 실행되는 user service를 권한상승으로 표시
- writable 객체가 read-only mount 또는 격리 namespace 때문에 영향이 없는 경우
- trigger가 없거나 비활성인 unit을 자동 실행 가능한 것으로 표시
- ACL과 상위 디렉터리 traverse 권한을 무시
- `nosuid` mount의 SUID를 유효하다고 표시
- 해석하지 못한 systemd specifier를 임의의 path로 확정

### 14.3 Adapter contract tests

가짜 PTY와 fixture backend로 다음을 재현한다.

- prompt와 command echo 혼입
- marker가 여러 read에 걸쳐 분할됨
- stdout/stderr 병합
- timeout과 output truncation
- 연결 중단 및 재개
- 비동기 task의 지연, 순서 변경, cancel 및 plugin crash

모든 adapter는 동일 contract test suite를 통과해야 한다.

### 14.4 통합 테스트

- 일반 probe와 non-systemd fallback은 컨테이너 fixture에서 검증
- 실제 systemd와 cgroup 동작은 경량 VM fixture에서 검증
- Debian/Ubuntu 계열, RHEL 호환 계열과 Alpine 계열을 대표 fixture로 사용
- SSH, raw shell과 C2 스타일 예제 adapter가 같은 host fact에서 동등한 후보를 생성하는지 비교
- 테스트 전후 service 상태와 fixture가 관리하는 애플리케이션·설정 path가 바뀌지 않았고 도구가 파일을 생성하지 않았는지 확인. read access time과 예상 가능한 audit/access log는 별도로 기록하고 동일성 비교에서 제외

## 15. MVP 완료 조건

다음 조건을 모두 충족해야 MVP가 완료된 것으로 본다.

1. SSH, raw listener와 stdio bridge가 공통 adapter contract를 만족한다.
2. C2 스타일 참조 plugin이 비동기 exec/poll/cancel 흐름을 입증한다.
3. systemd가 있는 fixture에서 process → unit → trigger → dependency → permission 관계를 생성한다.
4. systemd가 없는 fixture에서 cron/SysV와 바이너리 조사로 fallback한다.
5. 동일 fixture에 대해 adapter 종류와 관계없이 의미상 같은 후보를 생성한다.
6. 중단된 스캔을 완료 checkpoint부터 중복 없이 재개한다.
7. 각 candidate가 evidence와 missing fact를 참조한다.
8. 테스트 fixture의 P0/P1/P2 예상 결과와 negative case가 통과한다.
9. 기본 실행이 타깃의 서비스 및 애플리케이션·설정 파일 지속 상태를 의도적으로 변경하지 않으며, 도구가 타깃 파일을 생성하지 않는다.
10. 터미널 및 JSON 보고서가 민감값 정책을 준수한다.

## 16. 후속 범위

MVP 이후에만 다음을 고려한다.

- 실제 C2 제품별 adapter
- 선택적 정적 process observer
- 안전하게 격리된 temporary-artifact 검증
- OpenRC 심층 지원
- 더 긴 다단계 privilege path 탐색
- rule pack 버전 관리와 서명
- HTML 보고서 및 팀 협업용 export
- Windows collector
