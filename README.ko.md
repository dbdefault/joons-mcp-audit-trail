# JOONS MCP Audit Trail

AI 에이전트와 MCP 도구 활동을 위한, 덧붙이기 전용이며 변조를 알아챌 수 있는 감사 로그입니다. 모든 기록에는 자신의 내용과 직전 기록의 해시가 들어 있어, 수정, 삭제, 순서 바꾸기, 끼워 넣기를 `verify`가 찾아냅니다. 선택 사항인 키 파일(HMAC-SHA256)을 쓰면 키를 가진 사람만 그 키로 검증이 통과하는 체인을 만들 수 있습니다. 단, 검증할 때 키를 함께 줘야 하며 `--require-keyed`를 쓰는 것이 가장 좋습니다. 선택 사항인 앵커 파일을 쓰면 가장 최근 기록이 잘려 나간 것을 알 수 있습니다. Node.js 20 이상에서 동작하는 오프라인 명령줄 도구이자 작은 라이브러리이며, 실행 시점과 개발 시점의 의존 패키지, 네트워크 접속, 원격 측정이 전혀 없습니다.

영어판: [README.md](README.md)

## 솔직한 적용 범위

이 도구는 변경을 감지할 뿐 막지는 못합니다. 로그를 다시 쓸 수 있고 키까지 가진 공격자, 또는 키 없는 모드에서 모든 해시를 다시 계산할 수 있는 공격자는 로그를 위조할 수 있습니다. 끝부분 잘라내기는 앵커나 알고 있는 기록 개수와 비교할 때만 감지됩니다. 시각은 호출자가 넣은 주장일 뿐 신뢰할 수 있는 시간이 아닙니다. 누가 기록을 썼는지는 인증하지 않으며, 한 번 쓰면 바꿀 수 없는 저장소를 대신하지도 않습니다.

키도 앵커도 없으면, 키 없는 로그처럼 보이게 다시 쓴 로그는 진짜 키 없는 로그와 구별할 수 없습니다. `verify`는 로그 헤더가 스스로 밝힌 모드를 기준으로 검사합니다. 키 모드에 의지한다면 항상 `--key-file`과 `--require-keyed`로 검증하거나, 다른 곳에 보관한 앵커와 비교하십시오.

## 설치

```sh
npm install -g github:dbdefault/joons-mcp-audit-trail#v0.1.0
joons-mcp-audit-trail --version
```

npm 레지스트리에는 올라가 있지 않습니다. 설치 없이 써 보려면 내려받은 폴더에서 `node bin/joons-mcp-audit-trail.js`를 실행하십시오.

## 명령

```text
joons-mcp-audit-trail append <log> --type TYPE [--actor A] [--tool T] [--outcome OUTCOME] [--data FILE] [--time ISO] [--key-file FILE]
joons-mcp-audit-trail verify <log> [--anchor FILE] [--key-file FILE] [--require-keyed] [--format terminal|json]
joons-mcp-audit-trail anchor <log> --out FILE [--key-file FILE] [--force]
joons-mcp-audit-trail show <log> [--from N] [--to N] [--format terminal|json]
joons-mcp-audit-trail summary <log> [--details] [--format terminal|json|markdown]
joons-mcp-audit-trail export <log> --out FILE --format json|csv [--force]
joons-mcp-audit-trail --help | --version
```

옵션은 `--이름=값` 또는 `--이름 값` 형태로 쓸 수 있고, `<log>` 인자의 앞에 오든 뒤에 오든 상관없습니다(`summary audit.jsonl --details`뿐 아니라 `summary --details audit.jsonl`도 동작합니다). 모르는 옵션, 반복된 옵션, 값이 빠진 옵션, 그 명령에 맞지 않는 옵션, 단독 `--`, 남는 위치 인자는 모두 사용법 오류입니다. 표준 입력, 설정 파일, 환경 변수에 따른 동작은 없습니다. `--help`와 `--version`은 다른 인자 없이 단독으로만 쓸 수 있습니다.

| 옵션 | 뜻 |
| --- | --- |
| `--type TYPE` | `append`에 필수입니다. 영문자, 숫자, `.`, `_`, `:`, `-`로 이루어진 1~64자입니다. |
| `--actor A`, `--tool T` | 선택. 1~128자의 출력 가능한 이름입니다. 제어 문자, 보이지 않는 문자, 양방향 문자, 서식 문자, 변이 선택자, 태그 문자, 사용자 지정 영역 문자, 기본 무시 가능 코드 포인트와 배정되지 않은 코드 포인트, 그리고 ASCII 공백이 아닌 모든 공백(줄 바꿈 없는 공백, 전각 공백, 줄·문단 구분자 등)은 거부됩니다. 그래서 `agent`와 `agent`에 줄 바꿈 없는 공백을 붙인 이름이 서로 다른 두 이름이 될 수 없습니다. 이름이 글자 그대로 `(other)`(summary가 넘친 이름을 모아 두는 칸의 표시)인 경우, 그리고 ASCII 공백으로 시작하거나 끝나는 경우(공백만으로 된 이름 포함)도 비슷해 보이는 이름이므로 거부합니다. 이 검사들은 쓸 때 적용됩니다. 유니코드 검사는 `append`를 실행하는 Node.js의 유니코드 자료를 따르지만, 저장된 기록을 읽을 때는 그 자료와 무관한 고정 표를 씁니다(LIMITATIONS.md 참고). 사용 안내: 쓰기 검사는 제로 폭 결합자와 비결합자(U+200D, U+200C), 변이 선택자도 거부합니다. 그래서 가족 이모지 같은 결합 이모지, U+FE0F가 필요한 이모지(빨간 하트, 키캡), 결합자가 필요한 페르시아어·인도계 문자 이름은 actor와 tool 이름으로 쓸 수 없습니다. 국기, 피부색 이모지, 한중일 문자, 한글, 아랍어, 히브리어, 결합 문자는 쓸 수 있습니다. |
| `--outcome OUTCOME` | 선택. `ok`, `allow`, `deny`, `error`, `info` 중 하나입니다. |
| `--data FILE` | 선택. JSON 객체 파일(UTF-8, BOM 없음)이며 32 KiB 이하, 깊이 6 이하, 객체당 키 64개 이하, 배열당 원소 64개 이하, 문자열은 4,096자 이하입니다. 일반 파일이어야 합니다. 숫자는 값으로 읽습니다. 안전한 정수를 뜻하는 `1.0`과 `1e2`는 받아들여 `1`과 `100`으로 저장하고, 정수가 아닌 수는 `invalid_record`로 거부합니다. 파일이 32 KiB보다 크면 `limit_exceeded`이고, 파일은 더 작아도 정규 형태가 32 KiB보다 커지면(`1e9`는 `1000000000`으로 바뀝니다) `invalid_record`입니다. 한 객체 안에서 같은 키가 (어느 깊이에서든) 두 번 나오면 `invalid_record`로 거부하며, 중복을 조용히 처리하지 않습니다. |
| `--time ISO` | `2026-01-01T00:00:00Z` 또는 `2026-01-01T00:00:00.123Z` 같은 UTC 시각입니다. 소수부가 있으면 정확히 세 자리여야 합니다(`.123`은 되고 `.1`이나 `.1234`는 안 됩니다). 기본값은 현재 시각이며, 잠금을 얻은 뒤에 읽고 마지막 기록의 시각보다 이르게 하지 않으므로 `--time` 없이 동시에 append해도 모두 성공합니다. 시스템 시계가 거꾸로 가면 기록을 버리지 않고 마지막 기록의 시각을 씁니다. 명시한 `--time`은 마지막 기록의 시각보다 이르면 안 되고(같은 시각은 괜찮습니다), 이르면 `append`는 `invalid_record`로 실패하며 아무것도 쓰지 않습니다. 첫 append에서는 헤더 시각도 정합니다. |
| `--key-file FILE` | 4 KiB 이하, 16바이트 이상인 키 파일입니다(끝의 줄 종결자 정확히 한 개, 즉 `\n` 또는 `\r\n`이 제거되므로 CRLF로 저장한 키는 LF로 저장한 같은 키와 같습니다. 줄 종결자만 들어 있는 파일은 `key_invalid`입니다). 일반 파일이어야 합니다. |
| `--require-keyed` | `verify` 전용입니다. `--key-file`이 필요하며, 로그 헤더가 키 모드가 아니면 발견 사항을 보고합니다. |
| `--anchor FILE` | 로그와 맞춰 볼 앵커 파일입니다. |
| `--out FILE`, `--force` | `anchor`와 `export`의 출력 파일입니다. 이미 있는 파일은 `--force`가 없으면 거부되며, `--force`를 줘도 출력이 로그, 키 파일 또는 다른 입력 파일과 같은 파일이면 안 됩니다. |
| `--format` | `verify`와 `show`는 `terminal` 또는 `json`, `summary`는 `terminal`, `json`, `markdown`, `export`는 `json` 또는 `csv`(여기서는 필수)입니다. |
| `--from N`, `--to N` | `show`의 시작과 끝 일련번호(포함)이며 1 이상입니다. 한 번에 최대 10,000개입니다. |
| `--details` | `summary`가 서로 다른 이름의 개수만 보여 주는 대신 모든 이름과 횟수를 나열합니다. |

## 빠른 시작(키 없는 모드)

패키지에는 같은 이벤트 데이터가 `examples/event.json`으로, 같은 명령이 `examples/session.txt`로 들어 있습니다(`--time` 값이 고정되어 있어 로그가 같게 재현됩니다). `session.txt`의 명령은 패키지 루트 폴더에서 실행하십시오. `examples/event.json`을 상대 경로로 가리키기 때문입니다. JSON 파일을 직접 만들려면 쓰는 셸에 맞는 형태를 고르십시오. POSIX 셸(리눅스, macOS, Git Bash)에서는 다음과 같이 합니다.

```sh
printf '%s\n' '{"action":"read","path":"report"}' > event.json
```

Windows `cmd`에서는 다음과 같이 합니다(`>` 앞에 공백을 두지 않습니다).

```bat
echo {"action":"read","path":"report"}> event.json
```

PowerShell에서는 BOM 없는 UTF-8로 파일을 명시적으로 쓰십시오. 이때 `>`나 `Out-File`은 쓰지 마십시오. Windows PowerShell 5.1은 리다이렉트를 UTF-16으로 저장하므로 `--data`가 `invalid_record`로 거부합니다.

```powershell
[IO.File]::WriteAllText("$PWD\event.json", '{"action":"read","path":"report"}', [Text.UTF8Encoding]::new($false))
```

그다음에는 어느 셸에서든 같습니다.

```text
joons-mcp-audit-trail append audit.jsonl --type tool.call --actor agent --tool search --outcome ok --data event.json --time 2026-01-01T00:00:00Z
joons-mcp-audit-trail append audit.jsonl --type tool.result --time 2026-01-01T00:00:01Z
joons-mcp-audit-trail verify audit.jsonl
```

`append`는 로그가 없으면 새로 만들고(폴더는 미리 있어야 합니다) `{"seq":1,"hash":"..."}`를 출력합니다. 모드는 첫 append에서 정해집니다. `--key-file`을 주면 키 모드, 주지 않으면 키 없는 모드이며, 이후 append도 같은 모드여야 합니다. 매 append는 잠금을 잡은 채 헤더와 마지막 기록만 읽어 검사하고, 체인 전체는 `verify`만 확인합니다. 저장되는 모든 줄은 기록의 정규형(키 정렬, 공백 없음)이므로 로그는 바이트 단위로 똑같이 재현됩니다.

## 키 모드

평소의 비밀 관리 절차로 무작위 16바이트 이상의 키 파일을 만들고, 로그와 떨어진 곳에 보관하며, 로그를 다루는 모든 명령에 같은 키를 주십시오.

```sh
joons-mcp-audit-trail append keyed.jsonl --type tool.call --key-file key.bin
joons-mcp-audit-trail verify keyed.jsonl --key-file key.bin --require-keyed
```

헤더에는 짧은 키 식별자만 저장되고 키 자체는 저장되지 않습니다. 키 로그를 키 없이 검증하면 `key_required`로 실패하고, 다른 키로 검증하면 `key_mismatch` 발견 사항(`key_id_differs`)이 나오며, 틀린 키로 append하면 `key_invalid`입니다.

키 모드는 검증할 때 키를 써야만 도움이 됩니다. 누군가 키 로그를 키 없는 로그(키 없는 헤더와 다시 계산한 해시)로 다시 쓰면, `verify --key-file`은 `key_mismatch`와 `header_not_keyed` 상세를 보고하고(종료 코드 1), `append --key-file`은 `key_invalid`로 실패합니다. `--require-keyed`는 같은 요구를 스크립트에서 분명히 드러냅니다. 다시 쓴 그 로그를 키도 앵커도 없이 검증하면 통과하는데, 진짜 키 없는 로그와 구별할 근거가 없기 때문입니다.

키는 준 그대로 쓰입니다. 키의 엔트로피는 검사하지 않으며, 저장되는 키 식별자는 그 키를 쓰는 모든 로그에서 같아서 그런 로그들을 서로 연결해 주고 로그를 가진 사람이 키를 오프라인으로 추측해 볼 수 있게 합니다. 그러니 길고 무작위인 키를 쓰십시오. 키를 잃으면 키 해시를 더는 확인할 수 없습니다. 키를 바꾸려면 새 로그를 시작하십시오.

## 앵커

앵커는 로그의 줄 수와 가장 최근 줄의 해시를 적어 둔 파일입니다. 로그를 쓰는 쪽이 바꿀 수 없는 곳에 보관하십시오.

```text
joons-mcp-audit-trail anchor audit.jsonl --out checkpoint.json
joons-mcp-audit-trail append audit.jsonl --type session.end --time 2026-01-01T00:00:02Z
joons-mcp-audit-trail verify audit.jsonl --anchor checkpoint.json
```

앵커를 만든 뒤 늘어난 로그는 그 앵커와 계속 일치합니다. 앵커보다 짧아진 로그는 `truncated_tail`로, 앵커가 가리키는 줄이 달라졌거나 앵커 파일이 잘못되었거나 앵커 자체의 해시가 맞지 않으면 `anchor_mismatch`로, 앵커의 모드나 키가 로그와 다르면 `mode_change`로 보고됩니다. `anchor`는 검증을 통과하지 못하는 로그에는 앵커를 만들어 주지 않고, 키 로그는 `anchor`와 `verify --anchor` 모두에 `--key-file`이 필요하며, 로그에 속하지 않는 키(틀린 키, 또는 키 없는 로그에 준 키)는 `key_invalid`입니다.

## 변조 시연

위 명령을 실행하면 네 줄(헤더와 이벤트 세 개)의 로그와 `checkpoint.json`(로그가 세 줄이었을 때 만든 것)이 남습니다. 사본을 하나 두고, 이벤트 한 곳을 바꾼 뒤 다시 검증해 보십시오. 한 줄짜리 `node` 명령은 어느 셸에서나 똑같이 동작합니다.

```text
node -e "const fs=require('fs');fs.copyFileSync('audit.jsonl','good.jsonl')"
node -e "const fs=require('fs'),p='audit.jsonl';fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace('agent','other'))"
joons-mcp-audit-trail verify audit.jsonl --anchor checkpoint.json
```

출력(종료 코드 1):

```text
verify: FAILED
records: 4
mode: sha256
head: 88e247c1bbfa12ac73c9f31902c823f913796c475eec9f66f576cff4ffdc59dc
finding: hash_mismatch seq=1 hash_differs
anchor: OK
```

수정한 기록에 저장된 해시는 그대로이므로 앵커는 여전히 OK로 나오고, 바뀐 내용이 저장된 해시와 맞지 않는 점이 발견됩니다. 대신 사본을 처음 두 줄까지만 남기고 잘라 내면 출력은 다음과 같습니다.

```text
node -e "const fs=require('fs'),p='good.jsonl';fs.writeFileSync(p,fs.readFileSync(p,'utf8').split('\n').slice(0,2).join('\n')+'\n')"
joons-mcp-audit-trail verify good.jsonl --anchor checkpoint.json

verify: FAILED
records: 2
mode: sha256
head: 9c50db729e8ae085d57ae152d3827cb6bab5d089342f003455a340f75df77a5e
finding: truncated_tail seq=- log_shorter_than_anchor
anchor: FAILED log_shorter_than_anchor
```

형식은 엄격합니다. 저장된 줄의 들여쓰기를 바꾸거나, 키 순서를 바꾸거나, 같은 키를 두 번 쓰거나, 숫자나 이스케이프의 표기를 달리하거나, BOM을 붙이거나, 줄을 공백으로 채우면 저장된 바이트가 달라지므로 해시가 그대로 맞더라도 `line_not_canonical` 상세와 함께 `bad_record`(또는 `bad_header`)로 보고됩니다.

키 없는 모드에서는 수정한 뒤 모든 해시를 다시 계산하면 검증을 통과하는 로그를 만들 수 있습니다. 그 문턱을 높이려면 `--require-keyed`를 쓰는 키 모드와 따로 보관한 앵커를 함께 쓰십시오. 실제 증거 자료로는 이 시연을 하지 마십시오.

## 로그 읽기

- `show`는 `--from`과 `--to` 범위의 기록을 출력합니다(기본은 1번부터, 최대 10,000개이며 기본 범위에서 기록이 그보다 많으면 `limit_exceeded`(종료 코드 2), 10,000개보다 넓은 범위는 `--from`과 `--to`를 둘 다 줄 때만 사용법 오류(종료 코드 3)이고, 둘 중 하나만 주었는데 선택된 기록이 10,000개를 넘으면 `limit_exceeded`(종료 코드 2)). 출력 크기도 16 MiB(16,777,216바이트)로 제한됩니다. `show`는 읽는 동안 바이트를 세다가 선택한 범위가 한도를 넘으려는 순간 출력을 만들기 전에 `limit_exceeded`로 멈춥니다. 한도는 실제로 써질 모든 바이트를 세며 JSON과 터미널 형식 끝의 `\n]\n`도 포함합니다. 합계가 정확히 16,777,216바이트이면 출력되고, 1바이트라도 넘으면 `limit_exceeded`입니다. 헤더(seq 0)는 보여 주지 않습니다.
- `summary`는 이벤트 수(헤더는 세지 않음), 가장 이른 시각과 가장 늦은 시각(시각으로 해석해 비교하므로 `...01Z`와 `...01.500Z`가 올바른 순서가 됩니다), 그리고 type, actor, tool, outcome별로 서로 다른 이름의 개수를 보고합니다. `--details`를 주면 이름마다 횟수를 보여 줍니다. 한 필드에는 서로 다른 이름이 최대 10,000개까지 담기고, 그 밖의 이름은 `(other)`로 묶어 세며 `(other)` 자체는 이름 수에 넣지 않습니다. 128 코드 포인트보다 긴 이름은 아예 저장하지 않고(조작된 로그로 `summary`의 메모리를 크게 쓰게 만들 수 없습니다) 역시 `(other)`로 묶어 셉니다. `--details` 출력은 형식에 관계없이 전체 16 MiB까지이며, 더 크면 `limit_exceeded`로 멈춥니다(`append`가 만들 수 없는 로그에서만 생길 수 있습니다). `--details`가 없는 출력은 작습니다.
- `export`는 헤더(`seq` 0)를 포함한 모든 줄을 보기 좋은 JSON으로, 또는 `seq,time,type,actor,tool,outcome,data,prev,hash` 열의 CSV로 씁니다. 기록을 같은 폴더의 임시 파일로 스트리밍해 쓴 다음 제자리로 옮기므로, 허용되는 가장 큰 로그에서도 메모리 사용량이 작게 유지되고, 실패한 내보내기는 출력 파일을 남기지 않습니다. 값이 `=`, `+`, `-`, `@`로 시작하는(앞의 공백 뒤에서도) CSV 칸에는 맨 앞에 `'`를 붙여 스프레드시트가 수식으로 실행하지 않게 합니다. `data` 칸은 데이터의 정규형 JSON(키는 코드 단위 순서이며 JSON 출력과 같은 순서)입니다. CSV 칸에서도 터미널 출력과 같은 규칙으로 위험한 글자를 바꿔 씁니다. 모든 열에 적용되며(조작된 로그의 type, actor, tool, outcome 열도 포함하고 data 열만이 아닙니다), 터미널이 바꾸는 코드 포인트는 각각 `\uXXXX`(또는 `\u{XXXXX}`) 글자로 써집니다. C0와 C1 제어 문자(탭, 캐리지 리턴, 줄 바꿈도 포함하므로 칸 안에 줄 바꿈이 그대로 들어가는 일은 없습니다), DEL, 줄·문단 구분자 U+2028과 U+2029, U+2800, U+FFFC, 보이지 않는 문자와 양방향 문자, 사용자 지정 영역과 배정되지 않은 코드 포인트가 여기에 해당합니다. 터미널, 마크다운, CSV 출력은 ASCII 공백이 아닌 공백 구분자(U+00A0, U+1680, U+2000~U+200A, U+202F, U+205F, U+3000)도 `?`로 바꿉니다(CSV는 이스케이프 글자). 칸 안의 글자 그대로의 역슬래시-u는 이 이스케이프와 구별할 수 없습니다.

`show`, `summary`, `export`는 모든 줄이 정규형의 올바른 기록이기를 요구하지만(손상되었거나 예상 밖인 줄, 즉 단독 `null`, 숫자, 배열, 매우 깊게 중첩된 줄이 있으면 `log_corrupt`로 멈춥니다) 해시는 검사하지 않습니다. 줄마다 형식이 멀쩡한 채로 이루어진 변조는 `verify`만 찾아냅니다. 0바이트 파일은 로그가 아닙니다. `summary`, `show`, `export`는 `log_corrupt`로 실패하고, `verify`는 `bad_header`를 보고하며, `append`는 새 로그로 취급합니다. 터미널 출력은 기본 무시 가능 코드 포인트이거나 일반 범주가 Cf, Cc, Co, Cs 또는 배정되지 않음(Cn)인 모든 코드 포인트, 서식 문자 22개(U+110BD, U+110CD, U+13430부터 U+1343F, U+1BCA0부터 U+1BCA3), 그리고 이전부터의 보이지 않는 문자와 양방향 문자 목록을 `?`로 바꿉니다. 어떤 코드 포인트가 배정되지 않은 것으로 보이는지는 도구를 실행하는 Node.js의 유니코드 버전에 따라 달라집니다. 터미널 출력에서는 바뀐 글자만 다른 두 이름(또는 두 객체 키)이 같은 글자로 찍혀 한 항목으로 합쳐집니다(둘 중 하나만 보이므로 횟수가 더해지지 않습니다). JSON 출력과 내보내기는 둘을 구별해 그대로 담으므로 정확합니다. JSON 출력은 JSON 이스케이프를 따르고 객체 키를 코드 단위 순서로 나열하며, DEL과 C1 제어 문자(U+007F부터 U+009F까지)는 `\u00XX`로 이스케이프합니다. 양방향 문자와 그 밖의 서식 문자는 설계상 그대로 통과하므로, 데이터로 다루고 확인 없이 터미널이나 편집기에 붙여 넣지 마십시오. 마크다운 출력은 모든 칸을 하나의 인라인 코드 조각으로 쓰고(울타리는 안에 있는 어떤 백틱 연속보다 깁니다), 그래서 마크업, 링크, 맨 주소(URL), 이메일 주소가 해석되지 않습니다. 세로 막대는 JSON 이스케이프 `\u007c`로 쓰고 줄바꿈은 공백으로 바꿉니다. 내보낸 파일에는 로그의 내용이 들어 있으니 로그와 똑같이 보호하십시오.

## 종료 코드와 오류

| 코드 | 뜻 |
| --- | --- |
| 0 | 성공(`verify`는 발견 사항 없음). |
| 1 | `verify`가 변조 또는 앵커 불일치를 찾았습니다. 오류 줄이 아니라 표준 출력의 보고서입니다. |
| 2 | 입력, 한도, 자격 증명, 키, 손상된 로그 오류. |
| 3 | 사용법 오류. |
| 4 | 출력, 쓰기, 잠금 오류. |

오류는 표준 오류에 `joons-mcp-audit-trail: KIND` 한 줄만 출력하며, 경로, 기록 내용, 키 정보는 절대 들어가지 않습니다.

`append`는 기록이 디스크에 안전하게 쓰인 뒤에 결과(`{"seq":N,"hash":"..."}`)를 출력합니다. 이 표준 출력 쓰기가 실패하면(예: 닫힌 파이프) 기록은 이미 남아 있는데도 종료 코드는 4가 됩니다. 종료 코드 4에서 다시 시도하는 래퍼는 같은 기록을 두 번 추가할 수 있으니, 다시 시도하기 전에 로그(`show` 또는 `verify`)를 확인하십시오.

| 종류 | 코드 | 언제 |
| --- | --- | --- |
| `input_unreadable` | 2 | 읽을 파일이 없거나 읽을 수 없거나 일반 파일이 아닙니다(파이프, 소켓, 장치, 심볼릭 링크, 하드 링크가 있는 파일, 폴더는 열지 않고 거부합니다). |
| `invalid_record` | 2 | 이벤트, 시각, 데이터 파일이 필드 규칙을 어기거나, 이벤트 시각이 마지막 기록보다 이릅니다. |
| `log_corrupt` | 2 | 로그에 손상되었거나 끝나지 않았거나 정규형이 아닌 줄이 있습니다(append, show, summary, export, anchor). 또는 show, summary, export에서 로그가 비어 있습니다(0바이트). |
| `limit_exceeded` | 2 | 크기, 개수, 범위 한도에 걸렸습니다. |
| `credential_detected` | 2 | 값이 자격 증명처럼 보여 거부되었습니다. |
| `key_required` | 2 | 키 로그나 키 앵커를 키 없이 사용했습니다. |
| `key_invalid` | 2 | 키 파일이 없거나 너무 짧거나 길거나 로그와 맞지 않습니다. |
| `usage_error` | 3 | 명령줄이 잘못되었습니다. |
| `output_error` | 4 | 파일을 쓸 수 없거나, 출력 파일이 이미 있거나, 출력이 입력 파일과 같은 파일입니다. |
| `lock_timeout` | 4 | 잠금 파일이 5초 동안 남아 있었습니다. |
| `internal_error` | 2 | 예상하지 못한 실패입니다. |

검증 발견 사항의 종류는 `bad_header`, `bad_record`, `hash_mismatch`, `chain_break`, `seq_gap`, `time_regress`, `mode_change`, `key_mismatch`, `truncated_tail`, `anchor_mismatch`, `trailing_garbage`이며, 최대 100개까지만 나열하고 더 있으면 `truncated_report`를 덧붙입니다. 같은 문제는 한 번만 보고합니다. `detail` 문구는 정해진 어휘에서만 나오고 기록 내용은 담지 않습니다. 기록 뒤에 붙은 쓰레기 줄 때문에 로그가 1,000,000줄을 넘으면 `verify`는 오류가 아니라 발견 사항(종료 코드 1)으로 보고합니다.

## 자격 증명은 휴리스틱으로 거부합니다

`append`는 `type`, `actor`, `tool`, 그리고 `data`의 모든 문자열과 키 이름에서 개인 키 머리글, 베어러 토큰, JWT, AWS, GitHub, GitLab, Slack, Stripe, Google, SendGrid, npm의 키처럼 보이는 값을 퍼센트 디코딩 최대 두 번까지 거쳐 찾아 거부합니다. 베어러 토큰은 `Bearer ` 뒤에 토큰 문자가 16자 이상 있어야 하고, JWT는 `eyJ`로 시작하며 각각 10자 이상인 base64url 구간 세 개여야 하며, 접두사 계열(예: AWS, GitHub)은 토큰의 시작에 있어야 하므로 `Bearer of good news`, `npm_install`, `ESG.report` 같은 평범한 말은 허용됩니다. 이는 보장이 아닌 휴리스틱입니다. 기록에 비밀 값을 넣지 마십시오.

## 잠금, 안전장치, 한도

`append`는 로그 옆에 잠금 파일을 만듭니다(이름은 로그의 실제 폴더에서 정해지며, 파일 이름의 대소문자를 구분하지 않는 환경에서는 파일 이름을 유니코드 NFC로 정규화하고 대소문자를 접어 씁니다). 잠금 파일은 배타적으로 만들고, 무작위 토큰을 써 넣고, 끝나면 그 토큰이 아직 들어 있을 때만 지웁니다. 로그를 연 뒤에는 두 번째 잠금도 얻습니다. 로그 파일의 장치 번호와 inode 번호에서 이름을 딴 숨김 파일 `.audit-id-<hex>.lock`이 로그 옆에 생기며, 첫 번째 잠금이 같은 파일의 다른 철자로 알아보지 못하는 경우에도 차례를 지키게 합니다. 잠금마다 최대 5초 기다리고, 새 줄을 디스크에 flush한 뒤에 두 잠금을 풉니다. 기본 시각은 두 잠금을 쥔 동안에만 읽습니다. 강제 종료된 프로세스가 남긴 잠금은 자동으로 지워지지 않습니다. 강제 종료 뒤에는 `<log>.lock`과 `.audit-id-<hex>.lock` 두 파일이 모두 남을 수 있고, 둘 다 없어질 때까지 다음 `append`는 5초 기다린 뒤 `lock_timeout`으로 실패합니다. 쓰는 프로세스가 없음을 확인한 다음 두 파일을 모두 직접 지우십시오. 이름이 `.lock`으로 끝나는 로그(예: `x.lock`)는 `x`에 대한 append를 막습니다. `x.lock`이 `x`의 잠금 파일 이름이기 때문입니다. `anchor`와 `export`는 잠금 파일인 `--out`을 거부하며(어느 입력이든 그 이름 잠금이나 신원 잠금, `.audit-id-<hex>.lock` 형태의 모든 이름, 이름이 `.lock`으로 끝나는 기존 파일), `--force`를 줘도 마찬가지이므로 쥐고 있는 잠금이 교체되는 일은 없습니다. 강제 종료된 내보내기나 앵커 생성은 대상 옆에 `.이름.<hex>.tmp` 임시 파일을 남길 수 있으며 직접 지워도 됩니다. 마지막 줄이 끝나지 않았거나 정규형이 아니면 `append`는 `log_corrupt`로 실패하며 자동 복구는 하지 않습니다.

경로는 파일을 건드리기 전에 글자 그대로 검사합니다. 거부하는 것은 슬래시와 역슬래시를 어떻게 섞어 쓰든 UNC 경로와 장치 네임스페이스 경로, NUL 바이트, 대체 데이터 스트림(`C:\` 말고 다른 곳의 콜론), `CON`, `NUL`, `COM1`, 위첨자 숫자가 붙은 `COM`과 `LPT`, `CLOCK$` 같은 Windows 장치 이름(확장자가 있든 없든, 모든 플랫폼에서), 점이나 공백으로 끝나는 이름, 그리고 Windows에서 로그 이름 안의 `~` 다음 숫자(8.3 별칭)입니다. 이미 있는 입력 파일(로그, `--data`, `--anchor`, `--key-file`)은 하드 링크가 하나뿐인 일반 파일이어야 하며, 심볼릭 링크, 폴더, 파이프, 장치는 열지 않고 거부합니다. 상위 폴더 구성 요소는 검사하지 않으므로, 심볼릭 링크나 정션으로 이어진 폴더 안의 로그도 받아들입니다. `--force` 없이 출력 파일을 만들 때는 파일을 절대 덮어쓰지 않도록 `fs.link`를 쓰므로 하드 링크를 지원하는 파일 시스템이 필요합니다(예: FAT는 안 됩니다).

한 줄은 65,536바이트, 로그는 256 MiB 또는 1,000,000개 기록까지이며, `show`가 만드는 출력은 16 MiB까지입니다. `verify`, `summary`, `export`는 파일을 스트리밍으로 읽으므로 메모리 사용량은 로그 크기가 아니라 가장 긴 줄과 서로 다른 이름의 수에 따라 달라집니다.

## 라이브러리

```js
import {appendRecord, verifyLog, createAnchor} from 'joons-mcp-audit-trail';

await appendRecord('audit.jsonl', {type: 'tool.call', actor: 'agent'}, {});
const checkpoint = await createAnchor('audit.jsonl', {});
const report = await verifyLog('audit.jsonl', {});
if (!report.ok) console.error('verification found a problem');
```

`appendRecord`의 세 번째 인자는 옵션 객체(`keyFile`, `now`)이며, 생략하거나 `undefined` 또는 `null`을 주면 옵션이 없는 것과 같습니다. 거부된 프로미스에는 위의 오류 종류 중 하나가 `kind` 속성으로 들어 있습니다. 전체 인터페이스는 [docs/API.md](docs/API.md)에 있습니다.

## 셸 참고

PowerShell에서는 공백이 든 경로를 작은따옴표로 감싸십시오. 이벤트 JSON은 명령줄에 쓰지 말고 파일에 담고, BOM 없는 UTF-8로 저장하십시오(빠른 시작 참고). Windows `cmd`에서는 경로를 큰따옴표로 감싸십시오. `CON`, `NUL`, `log:stream` 같은 이름은 로그, 출력, 키, 앵커, 데이터 경로로 모든 플랫폼에서 거부됩니다.

## 개발

이 명령들은 소스 체크아웃(저장소를 복제한 폴더)에서 동작하며, 설치된 패키지에는 시험과 스크립트가 들어 있지 않습니다. `npm test`는 빠른 시험 묶음을 실행합니다. `npm run test:long`(`scripts/run-long-tests.mjs`를 실행합니다)은 긴 실제 한도 시험도 실행합니다. 임시 폴더에 기록 1,000,000개(약 250 MB)짜리 실제 로그를 만들어 append 한도, `verify`, 256 MB 힙 제한 아래의 `export`를 확인하고, `show`의 바이트 한도를 위해 큰 기록 8,100개로 이루어진 262 MB 로그도, `summary`를 위해 64,000자짜리 actor를 가진 기록 4,000개로 이루어진 조작된 257 MB 로그도 확인합니다. 빈 디스크 공간이 1 GB보다 적으면 건너뛰며, `test/long-tests.enabled` 파일이 있을 때만 실행되는데 이 스크립트가 실행하는 동안 그 파일을 만듭니다.

## 더 보기

- [docs/FORMAT.md](docs/FORMAT.md) 기록과 앵커 형식, 검산용 값
- [docs/API.md](docs/API.md) 라이브러리 인터페이스
- [ARCHITECTURE.md](ARCHITECTURE.md) 구성 요소가 맞물리는 방식
- [SECURITY.md](SECURITY.md)와 [LIMITATIONS.md](LIMITATIONS.md) 이 도구가 막아 주는 것과 막아 주지 못하는 것
- [CHANGELOG.md](CHANGELOG.md)

라이선스: Apache-2.0. Copyright 2026 JOONS contributors.
