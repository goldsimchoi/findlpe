# LPECO MVP 구현 계획

> **Required sub-skill:** 구현 시 `superpowers:executing-plans`를 사용하고, 각 기능은 `superpowers:test-driven-development`의 red-green-refactor 순서로 진행한다.

**Goal:** 승인된 Linux 권한상승 후보 오케스트레이터 설계를 `lpeco` Go 단일 바이너리와 C2 스타일 참조 어댑터로 구현하고, 세 가지 내장 transport, 증거 그래프, 11개 후보 규칙, 재개 가능한 저장소와 안전성 검증을 포함한 MVP 완료 조건 10개를 모두 충족한다.

**Architecture:** transport는 공통 `adapter.Adapter` 뒤에 격리하고, 고정 probe registry와 안전 정책을 거친 명령만 타깃에서 실행한다. 수집 결과는 immutable evidence와 typed fact로 로컬 store에 기록하고, graph builder가 privilege 관계를 구성한다. typed rule engine은 그래프와 증거 완전성을 함께 평가하여 P0/P1/P2 후보를 생성하며 reporter가 terminal/JSON으로 출력한다.

**Tech Stack:** Go 1.26, 표준 라이브러리, `golang.org/x/crypto/ssh`, `golang.org/x/term`, Go `testing`, golden fixtures, Linux container/VM integration fixtures, Makefile.

**Spec:** `docs/superpowers/specs/2026-10-12-linux-privesc-candidate-orchestrator-design.md`

**Global Constraints:**

- 승인된 환경의 방어적·검증 중심 열거 도구이며 exploit, 권한상승 실행, payload 생성 기능을 넣지 않는다.
- 타깃에서 서비스 제어, 파일 생성·수정·삭제, 권한 변경, 쓰기 기반 검증, 인증 시도, 비밀번호 대입을 하지 않는다.
- 기본 실행은 `passive-read`만 허용한다. `observable-read`는 사용자 opt-in과 실행 전 probe ID 고지를 요구한다. `temporary-artifact`와 `state-changing`은 scheduler에서 항상 거부한다.
- 타깃 유래 문자열은 collector가 셸 명령에 연결하지 않는다. 고정 script와 중앙 POSIX argv encoder만 사용한다.
- raw evidence는 parser 실패 때도 보존한다. 권한 거부, 잘림, 불명확성은 음성 증거로 해석하지 않는다.
- 모든 fact와 graph edge는 evidence ID를 가지며, 모든 candidate는 evidence ID와 missing facts를 가진다.
- 낮은 confidence 후보는 P0가 될 수 없고, 더 높은 principal이 없는 항목은 inventory에만 남긴다.
- 원시 evidence는 운영자 로컬에만 0600으로 저장하고, 세션 디렉터리는 0700으로 만든다. 보고서에는 원시 비밀값을 복제하지 않는다.
- 타깃 helper, 업로드와 다운로드를 MVP core가 호출하지 않는다.
- kernel 정보는 metadata일 뿐이며 CVE나 kernel exploit을 추천하지 않는다.
- unrelated workspace 파일은 건드리거나 커밋하지 않는다. 모든 제품 코드는 `lpeco/` 아래에 둔다.

**Review Focus:**

1. raw shell marker가 여러 read로 분할되거나 prompt/echo/noise가 섞이고 종료 marker가 사라져도 성공으로 오판하지 않는가.
2. systemd drop-in precedence, 빈 값 reset, 여러 `Exec*`, quoting, prefix, specifier와 timer/socket/path activation을 실제 의미대로 보존하는가.
3. symlink, parent traverse/write, ACL mask, sticky directory, read-only/noexec/nosuid mount를 함께 계산하며 `noexec`를 interpreted script에 잘못 적용하지 않는가.
4. partial/truncated/unavailable evidence나 unresolved specifier가 있는 후보가 P0/high confidence로 승격되지 않는가.
5. resume dedup, terminal/JSON redaction 및 전후 스냅샷이 중복 수집·비밀 유출·타깃 지속 상태 변경을 방지하는가.

## 구현 전 고정 계약

모든 명령은 별도 언급이 없으면 `/home/normalone/red/lpeco`에서 실행한다. 커밋은 workspace 루트 repository에 만들되 `lpeco/`와 이 계획에 명시한 문서만 stage한다.

### 디렉터리와 책임 맵

```text
lpeco/
├── cmd/
│   ├── lpeco/                  # 사용자 CLI
│   └── lpeco-c2-example/       # JSONL 비동기 참조 plugin
├── internal/
│   ├── model/                  # 공통 enum, evidence, fact, candidate, session
│   ├── store/                  # 0700/0600 session persistence와 dedup
│   ├── adapter/                # transport contract, command renderer
│   │   ├── raw/                # marker framing과 raw listener/stdio bridge
│   │   ├── ssh/                # SSH transport
│   │   └── plugin/             # subprocess JSON-RPC/JSONL transport
│   ├── probe/                  # registry, safety policy, adaptive planner
│   ├── collect/
│   │   ├── context/            # identity, namespace, LSM, init capability profile
│   │   ├── process/            # /proc snapshot과 관찰
│   │   ├── systemd/            # runtime/file unit 수집
│   │   ├── path/               # stat, ACL, symlink, mount와 effective control
│   │   ├── scheduler/          # cron과 SysV
│   │   ├── binary/             # sudo 단서, SUID/SGID, file caps, dependency
│   │   └── container/          # management socket
│   ├── systemdunit/            # unit lexing, merge, Exec/specifier 의미
│   ├── graph/                  # evidence-backed privilege graph
│   ├── rules/                  # 11개 typed validation rule
│   ├── orchestrator/           # phase, retry, fallback, checkpoint/resume
│   ├── redact/                 # 민감 데이터 마스킹
│   ├── report/                 # terminal/JSON reporter
│   └── cli/                    # flag parsing과 dependency wiring
├── testdata/                   # parser/rule/adapter golden fixture
├── test/integration/           # container, VM, cross-adapter, safety tests
├── docs/                       # 사용자·adapter 작성자 문서
├── Makefile
├── go.mod
└── go.sum
```

### 핵심 Go 계약

`internal/model`은 다음 안정적인 wire/domain 타입을 제공한다.

```go
type SafetyClass string
const (
    PassiveRead       SafetyClass = "passive-read"
    ObservableRead    SafetyClass = "observable-read"
    TemporaryArtifact SafetyClass = "temporary-artifact"
    StateChanging     SafetyClass = "state-changing"
)

type ProbeStatus string
const (
    ProbeComplete    ProbeStatus = "complete"
    ProbePartial     ProbeStatus = "partial"
    ProbeUnavailable ProbeStatus = "unavailable"
    ProbeTimeout     ProbeStatus = "timeout"
    ProbeTruncated   ProbeStatus = "truncated"
    ProbeParseError  ProbeStatus = "parse_error"
)

type Evidence struct {
    ID, SessionID, ProbeID, VariantID, Adapter, SHA256, InputFingerprint string
    StartedAt, FinishedAt time.Time
    Status ProbeStatus
    ExitCode *int
    MergedOutput, Truncated bool
    RelativePath string
}

type Fact struct {
    ID, Kind, SourceCollector string
    EvidenceIDs []string
    Confidence Confidence
    Data json.RawMessage
}

type Candidate struct {
    ID, RuleID, Category string
    Priority Priority
    Confidence Confidence
    CurrentPrincipal, TargetPrincipal NodeRef
    PrivilegedConsumer, ControlledObject, Trigger *NodeRef
    PathNodes []NodeRef
    EvidenceIDs, MissingFacts []string
    ValidationStatus ValidationStatus
    Summary string
}
```

`internal/adapter`의 transport 경계는 다음과 같다.

```go
type Capabilities struct {
    ProtocolVersion, TransportKind string
    Interactive, TTY, ReliableExitStatus, SeparateStderr bool
    AsyncTasks, Cancel bool
    MaxCommandBytes, MaxOutputBytes int
    Upload, Download bool
}

type ExecRequest struct {
    ProbeID, VariantID string
    Command Command
    Timeout time.Duration
    MaxOutput int
}

type ExecResult struct {
    Stdout, Stderr []byte
    ExitCode *int
    Status model.ProbeStatus
    MergedOutput, Truncated bool
    StartedAt, FinishedAt time.Time
}

type Adapter interface {
    Open(context.Context) (Capabilities, error)
    Exec(context.Context, ExecRequest) (ExecResult, error)
    Close(context.Context) error
}
```

`adapter.Command`는 registry가 소유한 고정 `Script`와 별도 `Args`만 받는다. `RenderPOSIX`가 `sh -c <fixed-script> lpeco <encoded-args...>` 형태로 한 곳에서 인코딩하며 collector에는 raw shell 문자열 API를 노출하지 않는다.

`internal/probe`의 정의 및 선택 계약은 다음과 같다.

```go
type Definition struct {
    ID, Collector, Parser, RedactionPolicy string
    SafetyClass model.SafetyClass
    Requirements []Requirement
    Variants []Variant
    Timeout time.Duration
    MaxOutput int
    Produces []string
    Idempotent bool
}

type Planner interface {
    Select(Definition, adapter.Capabilities, model.HostProfile, Policy) (Variant, error)
    ShouldRun(Definition, store.Checkpoint, Policy) Decision
}
```

store, graph, rule 경계는 다음과 같다.

```go
type SessionStore interface {
    Create(context.Context, model.Session) error
    Load(context.Context, string) (model.Session, error)
    PutEvidence(context.Context, model.Evidence, io.Reader) (model.Evidence, bool, error)
    AppendFacts(context.Context, []model.Fact) error
    LoadFacts(context.Context) ([]model.Fact, error)
    SaveCandidates(context.Context, []model.Candidate) error
    LoadCandidates(context.Context) ([]model.Candidate, error)
    SaveCheckpoint(context.Context, model.Checkpoint) error
}

type Rule interface {
    ID() string
    Evaluate(context.Context, *graph.Graph) []model.Candidate
}
```

## Task 1: Go module, 공통 모델과 ID 안정성

**Files:**

- Create: `lpeco/go.mod`
- Create: `lpeco/internal/model/enums.go`
- Create: `lpeco/internal/model/evidence.go`
- Create: `lpeco/internal/model/fact.go`
- Create: `lpeco/internal/model/graph.go`
- Create: `lpeco/internal/model/candidate.go`
- Create: `lpeco/internal/model/session.go`
- Test: `lpeco/internal/model/model_test.go`

**Interfaces:** 위의 model 계약, canonical JSON 기반 `StableID(prefix string, value any) (string, error)`.

1. `go mod init github.com/normalone/lpeco`로 module을 만들고 model enum JSON round-trip, 필수 필드 validation, map key 순서와 무관한 stable ID를 검증하는 테스트를 먼저 작성한다.
2. Run: `go test ./internal/model -run 'Test(EnumJSONRoundTrip|CandidateValidation|StableID)' -v`. Expected: 패키지 또는 symbol 부재로 FAIL.
3. 최소 enum/type, `Validate` 함수, canonical serialization과 SHA-256 기반 stable ID를 구현한다. candidate validation은 P0+low, 빈 evidence, 빈 target principal을 거부하고 실제 privilege boundary 판정은 rule 공통 rank 함수에서 수행한다.
4. Run: `go test ./internal/model -v && go test ./...`. Expected: PASS.
5. Commit: `git add lpeco/go.mod lpeco/internal/model && git commit -m "feat: define lpeco domain model"`.

## Task 2: 소유자 전용 session/evidence store와 dedup

**Files:**

- Create: `lpeco/internal/store/store.go`
- Create: `lpeco/internal/store/layout.go`
- Create: `lpeco/internal/store/jsonl.go`
- Test: `lpeco/internal/store/store_test.go`
- Test: `lpeco/internal/store/testdata/legacy-or-invalid-session.json`

**Interfaces:** `SessionStore`, `Open(baseDir, sessionID string) (*Store, error)`, `DefaultStateDir() (string, error)`.

1. temp directory에서 정확한 layout, directory 0700/file 0600, atomic metadata 교체, evidence SHA-256, `(session, probe, input fingerprint)` dedup, malformed/truncated JSONL 복구 실패를 테스트한다.
2. Run: `go test ./internal/store -v`. Expected: FAIL.
3. `os.UserConfigDir`가 아니라 XDG state 규칙을 명시적으로 구현한다. evidence body는 `evidence/<safe-probe-id>-<digest>.txt`, metadata는 `session.json`, fact는 append-only `facts.jsonl`, 후보는 `candidates.json`에 atomic rename으로 기록한다.
4. checkpoint에는 phase, 완료 probe fingerprint, retry count, pending validation을 저장한다. 같은 evidence 재입력은 body를 다시 쓰지 않고 `deduplicated=true`를 반환한다.
5. Run: `go test ./internal/store -race -v`. Expected: PASS.
6. Commit: `git add lpeco/internal/store && git commit -m "feat: persist resumable evidence sessions"`.

## Task 3: adapter contract, 안전한 command renderer와 probe planner

**Files:**

- Create: `lpeco/internal/adapter/adapter.go`
- Create: `lpeco/internal/adapter/command.go`
- Create: `lpeco/internal/adapter/contracttest/contract.go`
- Create: `lpeco/internal/probe/definition.go`
- Create: `lpeco/internal/probe/registry.go`
- Create: `lpeco/internal/probe/planner.go`
- Test: `lpeco/internal/adapter/command_test.go`
- Test: `lpeco/internal/probe/planner_test.go`

**Interfaces:** 위 `Adapter`, `Command`, `Definition`, `Planner`; sentinel errors `ErrUnsupported`, `ErrUnsafeProbe`, `ErrCommandTooLarge`.

1. apostrophe, newline, `$()`, backtick, leading dash와 NUL을 포함한 target-derived arg가 명령 실행으로 탈출하지 못하는 renderer 테스트를 먼저 만든다. NUL은 거부한다.
2. passive/observable/temporary/state-changing matrix, capability variant fallback, command/output limit, 완료 checkpoint skip, retry 최대 1회를 table test로 만든다.
3. Run: `go test ./internal/adapter ./internal/probe -v`. Expected: FAIL.
4. immutable registry와 중앙 renderer를 구현한다. registry duplicate ID와 동적 script 등록은 startup validation에서 거부한다.
5. planner는 observable probe 목록을 dry-run 결과로 먼저 반환하고 explicit policy bit 없이는 선택하지 않는다. 금지 등급에는 override API 자체를 제공하지 않는다.
6. Run: `go test ./internal/adapter ./internal/probe -race -v`. Expected: PASS.
7. Commit: `git add lpeco/internal/adapter lpeco/internal/probe && git commit -m "feat: add safe probe planning contracts"`.

## Task 4: raw marker framing, listener와 stdio bridge

**Files:**

- Create: `lpeco/internal/adapter/raw/frame.go`
- Create: `lpeco/internal/adapter/raw/parser.go`
- Create: `lpeco/internal/adapter/raw/adapter.go`
- Create: `lpeco/internal/adapter/raw/listener.go`
- Create: `lpeco/internal/adapter/raw/bridge.go`
- Test: `lpeco/internal/adapter/raw/frame_test.go`
- Test: `lpeco/internal/adapter/raw/adapter_test.go`
- Test: `lpeco/internal/adapter/raw/listener_test.go`
- Fixtures: `lpeco/testdata/adapter/raw/*.transcript`

**Interfaces:** `New(rwc io.ReadWriteCloser, opts Options) adapter.Adapter`, `Listen(ctx, ListenerOptions) (io.ReadWriteCloser, error)`, `StartBridge(ctx, []string) (io.ReadWriteCloser, error)`.

1. marker split at every byte boundary, prompt/banner/echo, CRLF, binary noise, merged stderr, missing start/end marker, malformed exit, truncation, timeout, disconnect를 contract test에 작성한다.
2. listener가 empty bind, wildcard bind without `AllowPublicBind`, 두 번째 connection, accept timeout을 거부하는 테스트를 작성한다. payload 문자열을 반환하는 API가 없음을 컴파일 경계로 유지한다.
3. Run: `go test ./internal/adapter/raw -v`. Expected: FAIL.
4. crypto/rand nonce와 control-character-delimited marker parser를 state machine으로 구현한다. probe는 mutex로 직렬화하고 end marker가 없으면 절대 complete를 반환하지 않는다.
5. `stdio bridge`는 명시한 child wrapper의 stdin/stdout을 raw framing에 연결하고 프로세스 종료/cancel을 정리한다. listener는 정확히 한 connection만 수락한다.
6. 공통 adapter contract suite를 raw와 stdio 양쪽에 적용한다.
7. Run: `go test ./internal/adapter/raw -race -v`. Expected: PASS.
8. Commit: `git add lpeco/internal/adapter/raw lpeco/testdata/adapter/raw && git commit -m "feat: add framed raw shell transports"`.

## Task 5: host-key 검증형 SSH adapter

**Files:**

- Create: `lpeco/internal/adapter/ssh/config.go`
- Create: `lpeco/internal/adapter/ssh/auth.go`
- Create: `lpeco/internal/adapter/ssh/adapter.go`
- Test: `lpeco/internal/adapter/ssh/config_test.go`
- Test: `lpeco/internal/adapter/ssh/adapter_test.go`
- Test helper: `lpeco/internal/adapter/ssh/testserver_test.go`

**Interfaces:** `New(Config) (*Adapter, error)`; config에 target, user, known_hosts, key path, agent socket, password callback, explicit insecure-host-key bool을 둔다.

1. host key mismatch/default verify, agent/key 우선순위, password callback의 메모리 한정 사용, timeout/cancel, stdout/stderr 분리, exit status와 truncation 테스트를 먼저 작성한다.
2. Run: `go test ./internal/adapter/ssh -v`. Expected: FAIL.
3. `x/crypto/ssh`, `knownhosts`, `ssh/agent`로 구현한다. password는 config serialization 대상이 아니며 session/evidence metadata에도 절대 전달하지 않는다.
4. embedded SSH test server로 공통 contract suite를 실행한다. handshake는 upload/download=false를 고정한다.
5. Run: `go test ./internal/adapter/ssh -race -v`. Expected: PASS.
6. Commit: `git add lpeco/go.mod lpeco/go.sum lpeco/internal/adapter/ssh && git commit -m "feat: add verified SSH transport"`.

## Task 6: subprocess JSON-RPC/JSONL plugin과 C2 스타일 예제

**Files:**

- Create: `lpeco/internal/adapter/plugin/protocol.go`
- Create: `lpeco/internal/adapter/plugin/client.go`
- Create: `lpeco/internal/adapter/plugin/process.go`
- Create: `lpeco/cmd/lpeco-c2-example/main.go`
- Create: `lpeco/cmd/lpeco-c2-example/backend.go`
- Test: `lpeco/internal/adapter/plugin/client_test.go`
- Test: `lpeco/cmd/lpeco-c2-example/backend_test.go`
- Fixtures: `lpeco/testdata/adapter/plugin/*.jsonl`

**Interfaces:** JSON-RPC methods `handshake/open_session/exec/poll/cancel/close_session`; protocol version `1`; `upload/download` method names reserved but uncalled.

1. delayed async completion, out-of-order event, duplicate event, cancel race, malformed JSON, protocol mismatch, process crash와 stderr diagnostic isolation 테스트를 먼저 만든다.
2. Run: `go test ./internal/adapter/plugin ./cmd/lpeco-c2-example -v`. Expected: FAIL.
3. scanner token limit에 의존하지 않는 bounded line decoder와 request-ID dispatcher를 구현한다. plugin crash는 `ProbePartial` 및 resumable session error로 변환한다.
4. fixture backend는 task ID를 반환하고 poll 횟수에 따라 complete, delay, fail, cancel을 재현한다. 실제 C2 API나 network callback은 포함하지 않는다.
5. core가 upload/download RPC를 호출하지 않는 spy assertion과 공통 adapter contract suite를 추가한다.
6. Run: `go test ./internal/adapter/plugin ./cmd/lpeco-c2-example -race -v`. Expected: PASS.
7. Commit: `git add lpeco/internal/adapter/plugin lpeco/cmd/lpeco-c2-example lpeco/testdata/adapter/plugin && git commit -m "feat: define async external adapter protocol"`.

## Task 7: capability, identity와 `/proc` process collector

**Files:**

- Create: `lpeco/internal/collect/collector.go`
- Create: `lpeco/internal/collect/context/probes.go`
- Create: `lpeco/internal/collect/context/parser.go`
- Create: `lpeco/internal/collect/process/probes.go`
- Create: `lpeco/internal/collect/process/parser.go`
- Create: `lpeco/internal/collect/process/observe.go`
- Test: `lpeco/internal/collect/context/parser_test.go`
- Test: `lpeco/internal/collect/process/parser_test.go`
- Test: `lpeco/internal/collect/process/observe_test.go`
- Fixtures: `lpeco/testdata/context/*`, `lpeco/testdata/proc/{debian,rhel,alpine,busybox,races}/*`

**Interfaces:** collector `Plan(Profile, Discovery) []probe.Definition`, `Parse(Definition, adapter.ExecResult) ([]model.Fact, error)`; typed `IdentityFact`, `NamespaceFact`, `ProcessFact`, `CgroupFact` payloads.

1. UID/GID/capability/namespace/LSM/init parsing과 BusyBox/minimal output golden tests를 만든다.
2. `/proc/<pid>/status`, cmdline NUL, exe/cwd/root symlink, cgroup, disappearing PID와 permission denied fixture를 만든다. environment probe 자체가 전체 environ을 evidence로 가져오지 않고 allowlist key만 target-side에서 선택하며, parser가 value에 secret classification을 붙이는지 테스트한다.
3. 짧은 프로세스의 repeated snapshot merge, PID reuse를 start time으로 분리, `--observe=0`, default 30초 scheduler를 fake clock으로 테스트한다.
4. Run: `go test ./internal/collect/context ./internal/collect/process -v`. Expected: FAIL.
5. 고정 read-only probes와 parsers를 구현한다. fd/maps는 고권한 또는 연결된 PID에만 후속 계획하고, 전체 environment는 요청하지 않는다.
6. 권한 거부와 race는 partial fact+missing fact로 기록하며 빈 결과로 지우지 않는다.
7. Run: `go test ./internal/collect/context ./internal/collect/process -race -v`. Expected: PASS.
8. Commit: `git add lpeco/internal/collect lpeco/testdata/context lpeco/testdata/proc && git commit -m "feat: collect execution context and processes"`.

## Task 8: systemd unit parser, merge와 Exec 의미

**Files:**

- Create: `lpeco/internal/systemdunit/lexer.go`
- Create: `lpeco/internal/systemdunit/parser.go`
- Create: `lpeco/internal/systemdunit/loadpath.go`
- Create: `lpeco/internal/systemdunit/merge.go`
- Create: `lpeco/internal/systemdunit/exec.go`
- Create: `lpeco/internal/systemdunit/specifier.go`
- Test: `lpeco/internal/systemdunit/lexer_test.go`
- Test: `lpeco/internal/systemdunit/merge_test.go`
- Test: `lpeco/internal/systemdunit/exec_test.go`
- Test: `lpeco/internal/systemdunit/specifier_test.go`
- Fixtures: `lpeco/testdata/systemd/unit/{debian,rhel,aliases,templates,dropins,quoting}/*`

**Interfaces:** `Parse(Source) (Document, []Diagnostic)`, `Merge(LoadContext, []Document) EffectiveUnit`, `ParseExec(string) ExecCommand`, `ExpandSpecifiers(string, SpecifierContext) (string, []MissingFact)`.

1. line continuation, comments, duplicate keys, quoted escapes, empty assignment reset, list/scalar merge, `/etc`→`/run`→`/usr/lib`→`/lib` precedence, alias/template/instance drop-in 순서를 golden test로 작성한다.
2. 모든 `ExecCondition/StartPre/Start/StartPost/Reload/Stop/StopPost`, `-:+!@|` prefix 조합, semicolon literal, environment expansion 차이와 simple executable name을 table test로 작성한다.
3. `%i/%I/%n/%N/%p/%u/%U/%g/%G/%h/%t/%%` known context와 unknown/custom specifier가 missing fact로 남는 테스트를 만든다.
4. Run: `go test ./internal/systemdunit -v`. Expected: FAIL.
5. parser와 provenance-bearing merge를 구현한다. 각 effective value는 source path/line/evidence를 보존하고 reset된 이전 값은 실행 edge를 만들지 않는다.
6. shell tokenizer를 재사용하지 않고 systemd 전용 tokenizer를 구현한다. 해석 불가능한 명령은 raw value와 diagnostic을 보존한다.
7. Run: `go test ./internal/systemdunit -race -v`. Expected: PASS.
8. Commit: `git add lpeco/internal/systemdunit lpeco/testdata/systemd/unit && git commit -m "feat: parse effective systemd execution semantics"`.

## Task 9: systemd runtime/file collector와 activation 관계

**Files:**

- Create: `lpeco/internal/collect/systemd/probes.go`
- Create: `lpeco/internal/collect/systemd/show.go`
- Create: `lpeco/internal/collect/systemd/files.go`
- Create: `lpeco/internal/collect/systemd/normalize.go`
- Test: `lpeco/internal/collect/systemd/show_test.go`
- Test: `lpeco/internal/collect/systemd/collector_test.go`
- Fixtures: `lpeco/testdata/systemd/show/*`, `lpeco/testdata/systemd/cat/*`

**Interfaces:** typed `UnitFact`, `UnitSourceFact`, `ExecFact`, `ActivationFact`, `UnitSecurityFact` payloads.

1. loaded/inactive/failed/oneshot, system/user manager, cgroup/PID mapping, timer/socket/path activation, restart policy, EnvironmentFile, ExecSearchPath, WorkingDirectory, RootDirectory/Image golden tests를 작성한다.
2. `systemctl show` 성공 + cat provenance, D-Bus denial, missing systemctl, localized error, truncated result와 file-only fallback을 테스트한다.
3. Run: `go test ./internal/collect/systemd -v`. Expected: FAIL.
4. machine-readable property probe를 우선하고 파일 parser fallback을 구현한다. runtime과 file 값이 다르면 runtime effective value를 사용하되 provenance와 diagnostic 양쪽을 보존한다.
5. timer의 implicit `.service`, 명시 Unit, socket/path activation을 `ActivationFact`로 정규화한다. user unit이 동일 principal이면 inventory flag를 설정한다.
6. Run: `go test ./internal/collect/systemd -race -v`. Expected: PASS.
7. Commit: `git add lpeco/internal/collect/systemd lpeco/testdata/systemd/show lpeco/testdata/systemd/cat && git commit -m "feat: collect systemd consumers and triggers"`.

## Task 10: symlink/ACL/mount 기반 effective-control 엔진

**Files:**

- Create: `lpeco/internal/collect/path/probes.go`
- Create: `lpeco/internal/collect/path/stat.go`
- Create: `lpeco/internal/collect/path/acl.go`
- Create: `lpeco/internal/collect/path/mountinfo.go`
- Create: `lpeco/internal/collect/path/resolve.go`
- Create: `lpeco/internal/collect/path/control.go`
- Test: `lpeco/internal/collect/path/stat_test.go`
- Test: `lpeco/internal/collect/path/acl_test.go`
- Test: `lpeco/internal/collect/path/mountinfo_test.go`
- Test: `lpeco/internal/collect/path/control_test.go`
- Fixtures: `lpeco/testdata/path/*`

**Interfaces:** `Resolve(path string, observations ObservationSet) Resolution`, `EvaluateControl(model.Principal, Resolution, UseKind) ControlAssessment`.

1. relative/absolute symlink, multi-hop, dangling link, loop, changed inode/race와 every-parent chain tests를 만든다.
2. owner/group/other, supplementary groups, named user/group ACL, ACL mask, default ACL 비적용, missing getfacl, sticky directory, non-traversable parent를 test matrix로 만든다.
3. escaped mountinfo path, nested mount, `ro/rw`, `noexec`, `nosuid`, bind mount와 remote/pseudo classification을 테스트한다. interpreted script에는 noexec만으로 control을 부정하지 않고 native executable/SUID에는 각각 반영한다.
4. Run: `go test ./internal/collect/path -v`. Expected: FAIL.
5. target write 없이 `stat/readlink/getfacl/mountinfo`만 사용하는 probes와 pure evaluator를 구현한다. replacement는 파일 write 또는 parent write+traverse+rename 조건을 구분한다.
6. ACL/mount/symlink 증거가 없으면 `Unknown`과 missing fact를 반환하며 writable로 낙관하지 않는다.
7. Run: `go test ./internal/collect/path -race -v`. Expected: PASS.
8. Commit: `git add lpeco/internal/collect/path lpeco/testdata/path && git commit -m "feat: evaluate evidence-backed path control"`.

## Task 11: cron/SysV, delegation, binary와 container fallback collector

**Files:**

- Create: `lpeco/internal/collect/scheduler/probes.go`
- Create: `lpeco/internal/collect/scheduler/parser.go`
- Create: `lpeco/internal/collect/binary/probes.go`
- Create: `lpeco/internal/collect/binary/sudo.go`
- Create: `lpeco/internal/collect/binary/elf.go`
- Create: `lpeco/internal/collect/binary/package.go`
- Create: `lpeco/internal/collect/container/socket.go`
- Test: `lpeco/internal/collect/scheduler/parser_test.go`
- Test: `lpeco/internal/collect/binary/parser_test.go`
- Test: `lpeco/internal/collect/container/socket_test.go`
- Fixtures: `lpeco/testdata/fallback/{cron,sysv,sudo,suid,capabilities,elf,packages,sockets}/*`

**Interfaces:** typed `ScheduleFact`, `DelegationFact`, `PrivilegedBinaryFact`, `DependencyFact`, `AdminSocketFact` payloads.

1. system/user crontab, `/etc/cron.d`, periodic directories, SysV runlevel links와 interpreter/script chains를 fixture로 테스트한다.
2. readable sudoers/include parsing과 `observable-read`인 `sudo -n -l`을 분리하고, password prompt/credential submission이 발생하지 않는 probe tests를 만든다.
3. SUID/SGID, `getcap`, ELF PT_INTERP/DT_NEEDED/RPATH/RUNPATH, shebang, dpkg/rpm/apk ownership과 unknown package manager fixture를 테스트한다.
4. unix socket mode/ACL과 실제 principal access가 있어야 container management fact가 생성되고 group 이름만으로 생성되지 않는 테스트를 작성한다.
5. filesystem walker가 `/proc,/sys,/dev`, runtime pseudo FS, remote mount, duplicate bind mount와 사용자 excludes를 건너뛰고 local mount를 한 번만 방문하는 테스트를 작성한다.
6. Run: `go test ./internal/collect/scheduler ./internal/collect/binary ./internal/collect/container -v`. Expected: FAIL.
7. 고정 read-only probes와 parsers를 구현한다. ELF는 Go에서 header/dynamic metadata만 읽고 실행하지 않는다. 기본 walker scope와 limit를 강제한다.
8. Run: `go test ./internal/collect/scheduler ./internal/collect/binary ./internal/collect/container -race -v`. Expected: PASS.
9. Commit: `git add lpeco/internal/collect/scheduler lpeco/internal/collect/binary lpeco/internal/collect/container lpeco/testdata/fallback && git commit -m "feat: collect fallback privilege surfaces"`.

## Task 12: evidence-backed privilege graph와 process/systemd 규칙

**Files:**

- Create: `lpeco/internal/graph/graph.go`
- Create: `lpeco/internal/graph/builder.go`
- Create: `lpeco/internal/graph/query.go`
- Create: `lpeco/internal/rules/rule.go`
- Create: `lpeco/internal/rules/rank.go`
- Create: `lpeco/internal/rules/systemd.go`
- Create: `lpeco/internal/rules/process.go`
- Test: `lpeco/internal/graph/builder_test.go`
- Test: `lpeco/internal/rules/systemd_test.go`
- Test: `lpeco/internal/rules/process_test.go`
- Fixtures: `lpeco/testdata/rules/{systemd,process}/*.json`

**Interfaces:** graph node/edge enums from spec, `Build([]model.Fact) (*Graph, []Diagnostic)`, `EvaluateAll(context.Context, *Graph, []Rule) []model.Candidate`.

1. stable node dedup, evidence-less edge rejection, fact conflict/partial preservation, serialization determinism을 graph tests로 작성한다.
2. 다음 5개 rule 각각에 positive fixture와 최소 2개 negative fixture를 먼저 만든다.
   - `systemd.writable-unit-source`
   - `systemd.writable-exec-chain`
   - `systemd.controlled-environment`
   - `systemd.controlled-search-path`
   - `process.replaceable-dependency`
3. negatives에 같은 user service, writable하지만 effective unit에 미적용된 drop-in, trigger 없음, read-only mount, unresolved specifier, environment file이 실제 path에 미사용된 경우를 포함한다.
4. Run: `go test ./internal/graph ./internal/rules -run 'Test(Graph|Systemd|Process)' -v`. Expected: FAIL.
5. graph builder와 typed rules를 구현한다. control-consumer-trigger의 직접 evidence 완전성을 기반으로 priority/confidence/validation status를 공통 rank 함수에서 계산한다.
6. low confidence 또는 unresolved 필수 edge는 P0를 반환할 수 없도록 rank 함수 invariant/property test를 추가한다.
7. Run: `go test ./internal/graph ./internal/rules -race -v`. Expected: PASS.
8. Commit: `git add lpeco/internal/graph lpeco/internal/rules lpeco/testdata/rules/systemd lpeco/testdata/rules/process && git commit -m "feat: rank process and systemd privilege paths"`.

## Task 13: scheduler/binary/delegation/container 규칙 완성

**Files:**

- Create: `lpeco/internal/rules/scheduler.go`
- Create: `lpeco/internal/rules/binary.go`
- Create: `lpeco/internal/rules/delegation.go`
- Create: `lpeco/internal/rules/container.go`
- Test: `lpeco/internal/rules/scheduler_test.go`
- Test: `lpeco/internal/rules/binary_test.go`
- Test: `lpeco/internal/rules/delegation_test.go`
- Test: `lpeco/internal/rules/container_test.go`
- Fixtures: `lpeco/testdata/rules/{scheduler,binary,delegation,container}/*.json`

1. 나머지 6개 rule 각각에 positive와 최소 2개 negative fixture를 먼저 만든다.
   - `scheduler.writable-command`
   - `binary.suid-sgid-control`
   - `binary.capability-boundary`
   - `binary.loader-path-control`
   - `delegation.sudo-policy`
   - `container.admin-socket-control`
2. negatives에 `nosuid`, file capability inventory뿐인 경우, unconfirmed loader path, package-owned but uncontrollable binary, sudo command target이 현재 principal과 동일, 알려진 docker group 이름만 있고 socket 접근 없음, inactive schedule을 포함한다.
3. Run: `go test ./internal/rules -run 'Test(Scheduler|Binary|Delegation|Container)' -v`. Expected: FAIL.
4. 규칙을 구현하고 privilege boundary가 없으면 inventory-only diagnostic을 내도록 한다. SUID bit preservation 또는 trigger가 불명확하면 최대 P1로 제한한다.
5. 모든 11개 rule ID가 registry에 정확히 한 번 포함되고 각 fixture가 candidate evidence/missing fact를 검증하는 coverage test를 추가한다.
6. Run: `go test ./internal/rules -race -v`. Expected: PASS.
7. Commit: `git add lpeco/internal/rules lpeco/testdata/rules && git commit -m "feat: complete typed candidate rule set"`.

## Task 14: phase orchestration, adaptive expansion과 resume

**Files:**

- Create: `lpeco/internal/orchestrator/orchestrator.go`
- Create: `lpeco/internal/orchestrator/phases.go`
- Create: `lpeco/internal/orchestrator/executor.go`
- Create: `lpeco/internal/orchestrator/resume.go`
- Test: `lpeco/internal/orchestrator/orchestrator_test.go`
- Test: `lpeco/internal/orchestrator/resume_test.go`

**Interfaces:** `Run(ctx, adapter, store, Options) (Result, error)`, `Resume(ctx, adapter, store, Options) (Result, error)`; phases `profile/context/primary/targeted-validation/fallback/finalize`.

1. fake adapter/store로 phase order와 “context → process/systemd → referenced path만 확장 → rule validation”을 테스트한다.
2. primary 결과에 P0/P1이 있으면 fallback을 생략하고, 0개이거나 `Full=true`일 때만 fallback하는 테스트를 만든다.
3. passive retry 최대 한 번, observable opt-in preview, 금지 safety class, raw sequential execution, async bounded parallelism을 테스트한다.
4. disconnect/plugin crash/timeout/truncation 뒤 checkpoint, completed fingerprint skip, evidence dedup와 pending validation 재개를 테스트한다.
5. Run: `go test ./internal/orchestrator -v`. Expected: FAIL.
6. phase state machine을 구현한다. parser error는 evidence 저장 후 parse_error로 바꾸며 전체 core panic/종료 대신 resumable error에 집계한다.
7. candidate 평가 후 필요한 read-only validation probes만 한 차례 계획하고 재평가한다. validation 무한 루프는 금지한다.
8. Run: `go test ./internal/orchestrator -race -v`. Expected: PASS.
9. Commit: `git add lpeco/internal/orchestrator && git commit -m "feat: orchestrate adaptive resumable scans"`.

## Task 15: redaction, terminal/JSON report와 CLI wiring

**Files:**

- Create: `lpeco/internal/redact/redact.go`
- Create: `lpeco/internal/report/terminal.go`
- Create: `lpeco/internal/report/json.go`
- Create: `lpeco/internal/cli/cli.go`
- Create: `lpeco/internal/cli/scan.go`
- Create: `lpeco/internal/cli/listen.go`
- Create: `lpeco/internal/cli/report.go`
- Create: `lpeco/cmd/lpeco/main.go`
- Test: `lpeco/internal/redact/redact_test.go`
- Test: `lpeco/internal/report/report_test.go`
- Test: `lpeco/internal/cli/cli_test.go`
- Fixtures: `lpeco/testdata/report/*`

**Interfaces/CLI:**

```text
lpeco scan ssh <target> [--user ... --key ... --known-hosts ...]
lpeco listen raw --bind <host:port> [--allow-public-bind --accept-timeout ...]
lpeco scan bridge --adapter '<command>' [--protocol jsonrpc|raw]
lpeco resume <session-id> [transport options]
lpeco report <session-id> --format terminal|json
```

공통 flags: `--state-dir`, `--observe=30s`, `--full`, `--observable-read`, `--scan-root`, `--exclude`, `--max-output`.

1. URL userinfo, `KEY=value`, bearer/basic tokens, common password/secret flags, allowlisted environment values와 process argv를 마스킹하는 table/fuzz tests를 만든다. 경로와 evidence ID는 유지한다.
2. terminal priority order, confidence/validation label, evidence/missing facts, observation limitations와 “confirmed exploit” 금지 문구를 golden test로 만든다.
3. JSON schema stability, raw evidence body 미포함, deterministic ordering과 secret absence tests를 만든다.
4. CLI parse/error tests에 public bind gate, host-key verification default, interactive password 비저장, observable probe preview/confirmation flag, invalid duration/format을 포함한다.
5. Run: `go test ./internal/redact ./internal/report ./internal/cli ./cmd/lpeco -v`. Expected: FAIL.
6. reporter와 CLI dependency wiring을 구현한다. `main`은 signal cancel과 의미 있는 exit code를 제공하며 panic detail/secret을 출력하지 않는다.
7. `go test -fuzz=FuzzRedact -fuzztime=10s ./internal/redact`를 실행해 발견한 case를 regression corpus로 저장한다.
8. Run: `go test ./internal/redact ./internal/report ./internal/cli ./cmd/lpeco -race -v && go build ./cmd/lpeco ./cmd/lpeco-c2-example`. Expected: PASS.
9. Commit: `git add lpeco/go.mod lpeco/go.sum lpeco/internal/redact lpeco/internal/report lpeco/internal/cli lpeco/cmd/lpeco lpeco/testdata/report && git commit -m "feat: expose safe CLI and reports"`.

## Task 16: cross-adapter integration, 무변경 안전성, 문서와 release gate

**Files:**

- Create: `lpeco/test/integration/fixtures/README.md`
- Create: `lpeco/test/integration/container/Dockerfile.debian`
- Create: `lpeco/test/integration/container/Dockerfile.alpine`
- Create: `lpeco/test/integration/container/fixture.sh`
- Create: `lpeco/test/integration/container_test.go`
- Create: `lpeco/test/integration/cross_adapter_test.go`
- Create: `lpeco/test/integration/safety_test.go`
- Create: `lpeco/test/integration/vm/README.md`
- Create: `lpeco/test/integration/vm/run.sh`
- Create: `lpeco/test/integration/vm/assert.sh`
- Create: `lpeco/Makefile`
- Create: `lpeco/README.md`
- Create: `lpeco/docs/adapter-protocol.md`
- Create: `lpeco/docs/safety-model.md`
- Create: `lpeco/docs/rules.md`
- Create: `lpeco/docs/fixtures.md`

1. Debian 계열 fixture에 systemd process→unit→timer/socket/path→dependency→permission 관계와 P0/P1/P2 cases를 만든다. Alpine fixture에는 non-systemd cron/SysV와 fallback cases를 만든다.
2. 동일 canned host transcript를 SSH, raw, stdio와 example plugin에 replay하여 candidate의 `rule_id`, principals, consumer, controlled object, priority가 의미상 동일한지 비교한다.
3. fixture가 관리하는 service 상태, application/config path의 content/mode/owner와 새 파일 목록을 scan 전후 snapshot한다. atime과 명시한 audit/access logs만 제외하고 그 외 차이가 있으면 실패시킨다.
4. 실제 systemd/cgroup VM runner를 작성해 loaded/inactive/failed/oneshot 및 activation 관계를 검증한다. runner는 명시된 disposable VM에서만 동작하고 host service를 건드리지 않도록 guard를 둔다.
5. container와 VM test에는 각각 `integration`과 `vm_integration` build tag를 사용한다. Make targets를 추가한다: `fmt`, `vet`, `test`, `test-race`, `test-integration`, `test-vm`, `build`, `verify`. `test-vm`은 fixture image가 없으면 명시적 SKIP가 아니라 setup error로 끝내고 README에 준비 절차를 적는다.
6. 사용자 문서에 authorized-use boundary, transport 예제, raw listener public bind 위험, evidence 위치/권한, observable-read 영향, resume/report 흐름과 알려진 관찰 한계를 적는다. adapter 문서에는 모든 RPC schema와 example transcript를 포함한다.
7. Run: `go fmt ./... && go vet ./... && go test ./... -race && go build -trimpath ./cmd/lpeco ./cmd/lpeco-c2-example`. Expected: PASS.
8. Run when fixture prerequisites are present: `make test-integration && make test-vm`. Expected: PASS, 그리고 10개 MVP 완료 조건을 `README.md` release checklist에서 evidence test 이름과 연결한다.
9. `git diff --check`, `git status --short`, `git diff --stat`, `go list -m all`로 formatting, unintended files와 dependency를 감사한다.
10. Commit only intended paths: `git add lpeco && git commit -m "test: verify lpeco MVP end to end"`.

### MVP 완료 조건 추적표

| # | 완료 조건 | 소유 Task | 최종 자동 검증 |
|---|---|---|---|
| 1 | SSH/raw listener/stdio bridge 공통 contract | 3, 4, 5 | `TestBuiltinAdaptersSatisfyContract` |
| 2 | C2 참조 plugin의 async exec/poll/cancel | 6 | `TestExamplePluginAsyncLifecycle` |
| 3 | systemd process→unit→trigger→dependency→permission | 7~12, 16 | `TestSystemdPrivilegeGraphIntegration` |
| 4 | non-systemd cron/SysV/binary fallback | 11, 13, 14, 16 | `TestNonSystemdFallbackIntegration` |
| 5 | adapter별 의미상 같은 후보 | 4~6, 16 | `TestCrossAdapterCandidateEquivalence` |
| 6 | checkpoint부터 중복 없는 resume | 2, 14 | `TestResumeFromCompletedCheckpointWithoutDuplicates` |
| 7 | candidate의 evidence와 missing facts | 12, 13 | `TestEveryCandidateReferencesEvidenceAndMissingFacts` |
| 8 | P0/P1/P2와 모든 rule negative case | 12, 13 | `TestAllRulesHavePositiveAndTwoNegatives` |
| 9 | 타깃 지속 상태와 파일 미변경 | 3, 7~11, 16 | `TestTargetPersistentStateUnchanged` |
| 10 | terminal/JSON 민감값 정책 | 15, 16 | `TestReportsContainNoSecrets` |

이 표의 테스트 이름은 구현 중 임의로 바꾸지 않는다. 더 작은 package test가 추가되더라도 release gate는 위 acceptance test를 직접 실행한다.

## 최종 검증 및 완료 감사

구현이 끝났다는 표현을 사용하기 전에 `superpowers:verification-before-completion`을 다시 적용하고 다음을 새로 실행한다.

```bash
cd /home/normalone/red/lpeco
make verify
make test-integration
make test-vm
go test ./... -run TestAllRulesHavePositiveAndTwoNegatives -count=1
go test ./... -run TestCrossAdapterCandidateEquivalence -count=1
go test ./... -run TestTargetPersistentStateUnchanged -count=1
go test ./... -run TestReportsContainNoSecrets -count=1
```

완료 감사표는 설계의 MVP 완료 조건 1~10 각각에 대해 구현 파일, 자동 테스트 이름, 마지막 실행 결과를 기록한다. VM 또는 외부 prerequisite 때문에 한 항목이라도 실행하지 못하면 MVP를 완료로 선언하지 않고 정확한 미검증 항목과 재현 명령을 보고한다.

그 다음 `superpowers:requesting-code-review`로 전체 diff의 범위·안전성·명세 충족 여부를 검토하고, 발견된 문제는 다시 TDD로 수정한다. 최종 handoff에는 binary 위치, 테스트 결과, 알려진 제한, git commit 목록만 간결하게 제시한다.
