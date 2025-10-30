---
name: web-security-analyzer
description: Analyze website structure and security vulnerabilities, then generate Excel reports. Takes URL and optional credentials to analyze site menus, methods, URL paths, parameters, vulnerability potential, and authentication requirements.
---

# 웹 보안 분석기 스킬

이 스킬은 웹사이트의 구조를 분석하고 기본적인 보안 취약점을 확인하여 엑셀 보고서를 생성한다.

## 사용 시점

이 스킬은 다음과 같은 상황에서 사용한다:
- 웹사이트의 구조와 기능을 체계적으로 분석하고 싶을 때
- 웹사이트의 기본적인 보안 상태를 점검하고 싶을 때
- 웹 애플리케이션의 엔드포인트와 파라미터를 문서화하고 싶을 때
- 보안 감사의 초기 단계로 기본 정보 수집이 필요할 때
- 웹사이트 분석 보고서를 엑셀 형식으로 생성해야 할 때

## 스킬 사용법

### 1. 입력 정보 수집

먼저 사용자에게 다음 정보를 요청한다:
- **대상 URL**: 분석할 웹사이트의 기본 URL
- **아이디**: 로그인이 필요한 경우 (선택사항)
- **패스워드**: 로그인이 필요한 경우 (선택사항)
- **분석 범위**: 전체 사이트 또는 특정 경로 (선택사항)

### 2. 웹사이트 분석 실행 (Chrome DevTools 또는 Playwright 사용)

Chrome DevTools MCP 서버를 사용하여 실제 브라우저 환경에서 웹사이트를 분석한다:

```python
# Chrome DevTools를 사용한 웹사이트 분석
# 1. 새 페이지 생성 및 네비게이션
await mcp__chrome_devtools__new_page(target_url)

# 2. 로그인 처리 (필요시)
if username and password:
    await mcp__chrome_devtools__fill_form([username_field, password_field])
    await mcp__chrome_devtools__click(login_button)

# 3. 페이지 스냅샷 및 구조 분석
await mcp__chrome_devtools__take_snapshot(verbose=True)

# 4. 네트워크 요청 분석
network_requests = await mcp__chrome_devtools__list_network_requests(pageSize=100, resourceTypes=["document", "script", "xhr", "fetch"])

# 5. 콘솔 메시지 확인 (에러 및 경고)
console_messages = await mcp__chrome_devtools__list_console_messages(types=["error", "warn", "log"])
```

또는 Playwright MCP 서버를 사용하여 자동화된 분석을 수행한다:

```python
# Playwright를 사용한 웹사이트 분석
# 1. 브라우저 시작 및 페이지 네비게이션
await mcp__playwright__browser_navigate(target_url)

# 2. 로그인 처리 (필요시)
if username and password:
    await mcp__playwright__browser_fill_form(fields=[username_field, password_field])

# 3. 페이지 스냅샷 및 요소 분석
page_snapshot = await mcp__playwright__browser_snapshot()

# 4. 네트워크 요청 모니터링
network_data = await mcp__playwright__browser_network_requests()

# 5. 콘솔 메시지 확인
console_errors = await mcp__playwright__browser_console_messages(onlyErrors=True)
```

### 3. Chrome DevTools/Playwright를 활용한 분석 항목

#### 페이지 구조 분석
- **DOM 트리 분석**: 페이지의 전체 구조와 요소 계층
- **내비게이션 메뉴**: 메뉴 구조와 링크 목록 추출
- **폼 요소 식별**: 모든 input, select, textarea 요소와 속성
- **자바스크립트 실행**: 동적으로 로드되는 콘텐츠 분석

#### 네트워크 분석
- **HTTP 요청/응답**: 모든 네트워크 활동 기록
- **API 엔드포인트**: XHR/Fetch 요청과 엔드포인트 목록
- **리소스 로딩**: CSS, JS, 이미지 등 리소스 로딩 순서
- **리다이렉션**: URL 리다이렉션 체인 분석

#### 보안 관련 분석
- **HTTPS 사용 여부**: SSL/TLS 설정 상태 확인
- **쿠키 정보**: 보안 관련 쿠키 속성(HttpOnly, Secure, SameSite)
- **CORS 정책**: Cross-Origin 요청 정책 확인
- **CSP 헤더**: Content Security Policy 설정 여부

### 4. 취약점 점검

Chrome DevTools의 개발자 도구와 네트워크 분석을 활용하여 취약점을 확인한다:

**Chrome DevTools 활용:**
```python
# 보안 탭 정보 확인
security_info = await mcp__chrome_devtools__evaluate_script("""
() => {
    return {
        https: window.location.protocol === 'https:',
        mixedContent: document.querySelectorAll('img[src^="http:"], script[src^="http:"]').length,
        cookies: document.cookie,
        localStorage: Object.keys(localStorage),
        sessionStorage: Object.keys(sessionStorage)
    }
}
""")
```

**네트워크 요청 분석:**
- 민감정보 포함 GET 요청 확인
- 인증 토큰 노출 여부 점검
- HTTP 대 HTTPS 요청 혼재 여부 확인
- API 응답에 민감정보 포함 여부 확인

### 5. 엑셀 보고서 생성

`scripts/excel_generator.py`를 사용하여 분석 결과를 엑셀 파일로 생성한다:

```python
import sys
sys.path.append('scripts')
from excel_generator import ExcelReportGenerator

# 분석 결과 통합
analysis_results = {
    'page_structure': page_structure_data,
    'network_analysis': network_data,
    'security_check': security_findings,
    'forms': forms_data,
    'endpoints': api_endpoints
}

# 보고서 생성
generator = ExcelReportGenerator(analysis_results)
generator.create_report('website_security_analysis.xlsx')
```

보고서에는 다음 시트가 포함된다:
- **요약 정보**: 분석 대상, 도구, 주요 발견사항
- **페이지 구조**: Chrome DevTools로 분석한 DOM 구조
- **네트워크 분석**: HTTP 요청/응답 상세 정보
- **폼 및 입력**: 발견된 폼과 파라미터 목록
- **API 엔드포인트**: XHR/Fetch 요청 엔드포인트
- **취약점 점검**: 보안 취약점 가능성 목록
- **쿠키 및 스토리지**: 쿠키와 로컬 스토리지 정보

### 6. 결과 검토 및 제공

생성된 엑셀 파일과 함께 Chrome DevTools/Playwright로 분석한 주요 발견사항을 요약하여 제공한다:
- 발견된 페이지 수와 동적 콘텐츠 현황
- 네트워크 요청 패턴과 API 엔드포인트
- 보안 설정 상태 및 잠재적 취약점
- 브라우저 콘솔 에러 및 경고 메시지
- 권장 개선 사항

## Chrome DevTools 활용 팁

### 페이지 분석 최적화
- **네트워크 탭**: 모든 리소스 로딩 순서와 타이밍 분석
- **Elements 탭**: 동적으로 변경되는 DOM 구조 확인
- **Console 탭**: 자바스크립트 에러와 경고 메시지 수집
- **Application 탭**: 쿠키, 로컬 스토리지, 세션 스토리지 확인
- **Security 탭**: HTTPS 설정 및 보안 상태 확인

### 동적 콘텐츠 분석
- 자동 스크롤을 통한 Lazy Loading 콘텐츠 로딩
- 클릭 이벤트를 통한 동적 메뉴 확장
- 폼 제출 후 결과 페이지 분석
- AJAX 요청으로 로드되는 콘텐츠 확인

## Playwright 활용 팁

### 자동화된 분석
- 여러 페이지 순회 및 분석 자동화
- 로그인 프로세스 자동화 및 인증 후 페이지 분석
- 스크린샷 캡처를 통한 시각적 분석 자료 수집
- 성능 측정을 통한 로딩 시간 분석

### 크롤링 및 데이터 수집
- 사이트맵 자동 생성 및 링크 순회
- 모든 내부 페이지의 구조 데이터 수집
- 반복적인 패턴의 폼과 입력 필드 식별
- 공통된 API 호출 패턴 확인

## 분석 항목 상세

### 메뉴 및 페이지 구조 (브라우저 기반 분석)
- 실제 렌더링된 내비게이션 메뉴
- 동적으로 생성되는 페이지 링크
- JavaScript 기반의 SPA 라우팅 구조
- 숨겨진 드롭다운 및 팝업 메뉴

### HTTP 메소드 및 엔드포인트 (네트워크 분석)
- 실제 발생하는 모든 HTTP 요청 기록
- XHR/Fetch를 통한 API 호출 패턴
- WebSocket 연결 및 통신 내용
- 리소스 로딩 타이밍 및 의존성

### 파라미터 분석 (DOM 및 네트워크)
- URL 쿼리 파라미터 및 경로 변수
- 폼 입력 필드 (type, name, validation)
- 요청 헤더 및 페이로드 파라미터
- 쿠키 및 스토리지 데이터

### 취약점 가능성 점검 (보안 분석)
- Mixed Content (HTTP/HTTPS 혼재)
- 인증 정보 노출 가능성
- 클라이언트 측 민감정보 저장
- CORS 및 CSP 정책 부재
- 쿠키 보안 속성 미설정

## 도구 선택 가이드

### Chrome DevTools 사용 권장
- 실시간으로 웹사이트와 상호작용하며 분석할 때
- 개발자 도구의 직관적인 인터페이스가 필요할 때
- 특정 페이지의 깊이 있는 분석이 필요할 때
- 성능 분석 및 디버깅이 필요할 때

### Playwright 사용 권장
- 대규모 웹사이트의 자동화된 분석이 필요할 때
- 여러 페이지를 순차적으로 분석해야 할 때
- 반복적인 테스트 및 분석이 필요할 때
- 스크린샷 및 시각적 자료 수집이 필요할 때

## 주의사항 및 제한사항

- 이 스킬은 기본적인 분석만 수행하며, 깊이 있는 보안 평가를 대체할 수 없다
- 분석 대상 웹사이트의 약관 및 robots.txt를 준수해야 한다
- 로그인 정보는 안전하게 처리되며, 보고서에 포함되지 않는다
- 동적 자바스크립트 기반 애플리케이션도 브라우저 기반 분석으로 대부분 확인 가능
- 분석 결과는 참고용이며, 전문 보안 감사가 필요한 경우 전문가의 검토를 받아야 한다
- Chrome DevTools/Playwright 사용 시 브라우저 리소스 소모에 유의해야 한다

## MCP 도구 사용 명령어

### Chrome DevTools 주요 명령어
```python
# 페이지 조작
mcp__chrome-devtools__new_page(url)
mcp__chrome-devtools__navigate_page(url)
mcp__chrome-devtools__take_snapshot(verbose=True)
mcp__chrome-devtools__list_network_requests()
mcp__chrome-devtools__list_console_messages()
mcp__chrome-devtools__evaluate_script(function)
mcp__chrome-devtools__fill_form(elements)
mcp__chrome-devtools__click(uid)
```

### Playwright 주요 명령어
```python
# 브라우저 조작
mcp__playwright__browser_navigate(url)
mcp__playwright__browser_snapshot()
mcp__playwright__browser_fill_form(fields)
mcp__playwright__browser_click(element, ref)
mcp__playwright__browser_network_requests()
mcp__playwright__browser_console_messages()
mcp__playwright__browser_evaluate(function)
mcp__playwright__browser_take_screenshot()
```

## 참고자료

- `references/vulnerability_checklist.md`: 취약점 점검 체크리스트
- `references/chrome_devtools_guide.md`: Chrome DevTools 활용 가이드
- `references/playwright_automation.md`: Playwright 자동화 스크립트 예제
- `assets/report_template.xlsx`: 보고서 템플릿 (선택사항)