# vuln-watch — 보안 취약점 소식 모아보기

여러 곳의 보안 취약점 소식을 1시간마다 자동으로 모아서 웹 페이지 하나로 보여줍니다.
GitHub가 수집과 호스팅을 모두 해주므로 내 PC에는 아무것도 설치하지 않아도 됩니다.

## 동작 방식

1. GitHub Actions가 매시 17분에 `collect.py`를 실행합니다.
2. 새 항목만 `docs/data.json`에 추가합니다. 이미 있는 항목은 건너뜁니다.
3. `docs/` 폴더를 GitHub Pages로 배포합니다. 브라우저로 그 주소를 열면 됩니다.

| 파일 | 역할 |
| --- | --- |
| `collect.py` | 수집기. Python 기본 기능만 써서 추가 설치가 없습니다. |
| `docs/index.html` | 화면. 필터, 검색, 내 제품 키워드. |
| `docs/data.json` | 모아둔 소식. 자동으로 갱신됩니다. |
| `.github/workflows/collect.yml` | 1시간마다 수집하고 배포하는 설정. |

## 수집하는 곳

| 출처 | 주소 | 비고 |
| --- | --- | --- |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | 공식 JSON. 여기 있는 CVE는 "공격에 악용 중"으로 표시 |
| KISA 보호나라 보안공지 | `boho.or.kr/kr/rss.do?bbsId=B0000133` | 공식 RSS. 새 글은 본문을 읽어 CVE 번호 추출 |
| BleepingComputer | `bleepingcomputer.com/feed/` | RSS |
| The Hacker News | `feeds.feedburner.com/TheHackersNews` | RSS |
| Microsoft 보안 업데이트 | `api.msrc.microsoft.com/update-guide/rss` | 최초 공개분만 수집 (수정 이력 제외) |
| Chrome Releases | `chromereleases.googleblog.com/feeds/posts/default` | 정식 채널 공지와 CVE가 있는 글만 |
| GitHub Advisory Database | `api.github.com/advisories` | 검토 완료된 권고 최신 100건 + maven(Java/Kotlin/Android), pub(Flutter), swift(iOS) 별도 수집 |

60일이 지난 항목은 자동으로 지워집니다. 기간은 `collect.py` 맨 위 `RETENTION_DAYS`에서 바꿉니다.

## 설치 (처음 한 번만)

### 1단계. GitHub 저장소 만들기

1. <https://github.com> 에 로그인합니다. 계정이 없으면 먼저 가입합니다.
2. 오른쪽 위 **+** → **New repository** 를 누릅니다.
3. **Repository name** 에 `vuln-watch` 를 입력합니다.
4. **Public** 을 선택합니다. 무료 계정은 공개 저장소에서만 Pages를 쓸 수 있습니다.
   저장소에는 공개된 뉴스만 들어가고, 내 제품 키워드는 저장소에 올라가지 않습니다.
5. "Add a README file" 등은 **체크하지 않고** **Create repository** 를 누릅니다.

### 2단계. 파일 올리기

이 폴더에서 터미널(Windows는 PowerShell)을 열고 아래를 한 줄씩 실행합니다.
`내아이디` 부분은 본인 GitHub 아이디로 바꿉니다.

```bash
git add .
```

```bash
git commit -m "취약점 소식 수집기"
```

```bash
git remote add origin https://github.com/내아이디/vuln-watch.git
```

```bash
git push -u origin main
```

Git이 없다면 <https://git-scm.com/downloads> 에서 설치합니다.

### 3단계. Pages 켜기

1. 저장소 페이지에서 **Settings** → 왼쪽 메뉴 **Pages** 로 갑니다.
2. **Build and deployment** 의 **Source** 를 **GitHub Actions** 로 바꿉니다. 저장 버튼은 따로 없습니다.

### 4단계. 첫 수집 실행

1. 저장소 위쪽 **Actions** 탭을 엽니다.
2. 왼쪽에서 **취약점 소식 수집** 을 고르고, 오른쪽 **Run workflow** → **Run workflow** 를 누릅니다.
3. 1~2분 뒤 초록색 체크가 뜨면 완료입니다.
4. `https://내아이디.github.io/vuln-watch/` 를 브라우저로 엽니다. 즐겨찾기에 추가해 두세요.

이후로는 1시간마다 자동으로 갱신됩니다.

## 화면 사용법

- **검색**: 제품명이나 CVE 번호를 입력합니다. 띄어 쓰면 모두 포함된 항목만 나옵니다.
- **영역 필터**: 서버 인프라 / 웹 개발 / 사내 PC. 제목과 요약의 단어로 자동 분류합니다.
- **공격에 악용 중**: CISA KEV 목록에 있는 CVE가 포함된 항목입니다. 빨간색으로 강조됩니다.
- **내 제품 키워드**: 쉼표로 구분해 입력하고 **저장** 을 누르면 해당 항목이 맨 위에 모입니다.
  키워드는 그 브라우저에만 저장됩니다. 다른 PC나 다른 브라우저에서는 다시 입력해야 합니다.
- 같은 날 같은 출처의 항목이 8건을 넘으면 한 줄로 접힙니다(예: Microsoft 정기 패치).
  눌러서 펼치거나 검색하면 낱개로 보입니다. 악용 중인 항목은 접히지 않습니다.
- 제목은 원문 그대로 표시합니다.

## 문제가 생겼을 때

- **페이지 아래 "수집 상태"에 실패가 보임**: 그 출처만 이번 회차에 못 받은 것입니다. 나머지는 정상이고, 다음 회차에 다시 시도합니다. 계속 실패하면 Actions 탭의 실행 기록에서 `[실패]` 줄을 확인합니다.
- **KISA만 계속 실패**: GitHub 서버(해외)에서의 접속을 KISA가 막는 경우입니다. PC에서 `python collect.py` 를 실행한 뒤 `docs/data.json` 을 커밋해 올리면 반영됩니다.
- **갱신이 늦음**: GitHub의 예약 실행은 붐빌 때 수십 분 늦어질 수 있습니다.
- **자동 수집이 멈춤**: Actions 탭에 "workflow was disabled" 안내가 보이면 **Enable workflow** 를 누릅니다.

## 내 PC에서 직접 돌려보기 (선택)

Python 3.9 이상이 필요합니다. Windows는 <https://www.python.org/downloads/> 에서 설치하고, 설치 첫 화면에서 **Add python.exe to PATH** 를 체크합니다.

```bash
python collect.py
```

```bash
python -m http.server 8765 --directory docs
```

그다음 브라우저로 <http://localhost:8765> 를 엽니다. `index.html` 을 더블클릭해서 열면 데이터가 표시되지 않습니다.

## 바꾸고 싶을 때

- **영역 분류 단어**: `collect.py` 의 `AREA_KEYWORDS`
- **수집 주기**: `.github/workflows/collect.yml` 의 `cron`
- **보관 기간**: `collect.py` 의 `RETENTION_DAYS`
