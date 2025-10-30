---
name: web-security-analyzer
description: Comprehensive web security vulnerability analyzer that crawls entire websites, extracts menu structures, analyzes HTTP requests with parameters and methods, identifies potential vulnerabilities including XSS and SQL injection patterns, and generates detailed Excel reports with menu-by-menu security analysis.
---

# 종합 웹 보안 분석기 스킬

이 스킬은 웹사이트 전체를 체계적으로 분석하여 모든 메뉴 구조와 보안 취약점을 식별하고, 상세한 엑셀 보고서를 생성한다. 공격을 수행하지 않고 코드 패턴과 요청 분석을 통해 취약점 가능성을 평가한다.

## 사용 시점

이 스킬은 다음과 같은 상황에서 사용한다:
- 웹사이트 전체의 보안 상태를 종합적으로 평가할 때
- 모든 메뉴와 기능별 취약점을 체계적으로 분석할 때
- XSS, SQL Injection을 포함한 다양한 취약점 패턴을 식별할 때
- 웹 애플리케이션의 모든 HTTP 요청과 파라미터를 문서화할 때
- 보안 감사를 위한 상세 분석 보고서가 필요할 때

## 분석 절차

### 1. 의존성 확인

스킬 실행을 시작하기 전 필수 의존성을 확인하고 설치한다:

```python
import subprocess
import sys
import importlib
from typing import Dict, List, Any

def check_mcp_servers() -> Dict[str, bool]:
    """MCP 서버 설치 여부 확인"""
    mcp_status = {
        'chrome-devtools': False,
        'playwright': False
    }

    print("🔍 MCP 서버 설치 여부 확인 중...")

    # Chrome DevTools MCP 확인
    try:
        # mcp__chrome_devtools__list_pages 같은 함수 호출로 확인
        test_result = mcp__chrome_devtools__list_pages()
        mcp_status['chrome-devtools'] = True
        print("✅ Chrome DevTools MCP 설치됨")
    except Exception as e:
        print(f"❌ Chrome DevTools MCP 미설치 또는 오류: {str(e)}")

    # Playwright MCP 확인
    try:
        # mcp__playwright__new_page 같은 함수 호출로 확인
        test_result = mcp__playwright__new_page("about:blank")
        mcp_status['playwright'] = True
        print("✅ Playwright MCP 설치됨")
    except Exception as e:
        print(f"❌ Playwright MCP 미설치 또는 오류: {str(e)}")

    return mcp_status

def install_python_libraries() -> bool:
    """필수 파이썬 라이브러리 설치 확인 및 설치"""
    required_libraries = {
        'pandas': 'pandas',
        'openpyxl': 'openpyxl',
        'chardet': 'chardet',
        'requests': 'requests'
    }

    missing_libs = []

    print("🔍 파이썬 라이브러리 확인 중...")

    # 라이브러리 설치 여부 확인
    for lib_name, package_name in required_libraries.items():
        try:
            importlib.import_module(lib_name)
            print(f"✅ {lib_name} 설치됨")
        except ImportError:
            print(f"❌ {lib_name} 미설치")
            missing_libs.append(package_name)

    # 누락된 라이브러리 설치
    if missing_libs:
        print(f"📦 누락된 라이브러리 설치 중: {', '.join(missing_libs)}")

        for package in missing_libs:
            try:
                print(f"📥 {package} 설치 중...")
                subprocess.check_call([
                    sys.executable, '-m', 'pip', 'install', package, '--quiet'
                ])
                print(f"✅ {package} 설치 성공")
            except subprocess.CalledProcessError as e:
                print(f"❌ {package} 설치 실패: {str(e)}")
                return False

        print("🎉 모든 라이브러리 설치 완료")

    return True

def validate_dependencies() -> bool:
    """스킬 실행 의존성 유효성 검사"""
    print("=" * 50)
    print("🚀 웹 보안 분석기 스킬 - 의존성 확인")
    print("=" * 50)

    # 1. MCP 서버 확인
    mcp_status = check_mcp_servers()

    # 둘 다 설치되어 있지 않으면 종료
    if not any(mcp_status.values()):
        print("\n" + "=" * 50)
        print("❌ 스킬 실행 불가")
        print("=" * 50)
        print("필수 MCP 서버가 설치되어 있지 않습니다:")
        print("  • Chrome DevTools MCP (브라우저 자동화)")
        print("  • Playwright MCP (웹 페이지 테스트)")
        print("\n설치 방법:")
        print("  Claude Code 설정에서 MCP 서버를 설치해주세요.")
        print("  자세한 설명: https://docs.claude.com/claude-code/mcp")
        print("=" * 50)
        return False

    # 최소 하나라도 있으면 경고 메시지
    if not all(mcp_status.values()):
        missing_servers = [name for name, installed in mcp_status.items() if not installed]
        print(f"\n⚠️ 일부 MCP 서버 미설치: {', '.join(missing_servers)}")
        print("스킬 기능이 제한될 수 있습니다.")

    # 2. 파이썬 라이브러리 설치
    if not install_python_libraries():
        print("\n❌ 필수 라이브러리 설치 실패")
        print("스킬을 실행할 수 없습니다.")
        return False

    print("\n" + "=" * 50)
    print("✅ 의존성 확인 완료 - 스킬 실행 가능")
    print("=" * 50)
    return True

# 스킬 시작 전 의존성 확인
if not validate_dependencies():
    raise Exception("스킬 실행을 위한 의존성이 충족되지 않습니다.")

```

### 2. 입력 정보 수집

분석을 시작하기 전 다음 정보를 수집한다:
- **대상 URL**: 분석할 웹사이트의 기본 URL
- **아이디**: 로그인이 필요한 경우 (선택사항)
- **패스워드**: 로그인이 필요한 경우 (선택사항)
- **분석 깊이**: 사이트 전체 또는 특정 영역 (기본값: 전체)

### 3. 사이트 전체 탐색 및 크롤링

Chrome DevTools를 사용하여 사이트 전체를 체계적으로 탐색한다. 에러 핸들링과 안정성을 최우선으로 고려한다:

```python
import asyncio
from typing import List, Dict, Any, Optional

# 분석 설정
MAX_PAGES = 100  # 최대 분석 페이지 수
PAGE_TIMEOUT = 10000  # 페이지 로딩 타임아웃 (ms)
RETRY_COUNT = 3  # 실패 시 재시도 횟수

async def safe_navigate(url: str, max_retries: int = RETRY_COUNT) -> bool:
    """안전한 페이지 네비게이션"""
    for attempt in range(max_retries):
        try:
            await mcp__chrome_devtools__navigate_page(url)
            # 페이지 로딩 대기
            await asyncio.sleep(2)
            return True
        except Exception as e:
            print(f"페이지 로딩 실패 (시도 {attempt + 1}/{max_retries}): {url} - {str(e)}")
            if attempt == max_retries - 1:
                return False
            await asyncio.sleep(1)
    return False

async def collect_links_safely() -> List[Dict[str, str]]:
    """안전한 링크 수집"""
    try:
        all_links = await mcp__chrome_devtools__evaluate_script("""
        () => {
            try {
                const links = [];
                const visitedUrls = new Set();

                // 내비게이션 메뉴 우선 수집
                const navSelectors = ['nav a', '.menu a', '.navigation a', '.navbar a', '.header a', '.sidebar a'];
                navSelectors.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach(link => {
                            if (link.href &&
                                link.href.includes(window.location.origin) &&
                                !link.href.includes('#') &&
                                !visitedUrls.has(link.href)) {
                                visitedUrls.add(link.href);
                                links.push({
                                    text: link.textContent.trim(),
                                    url: link.href,
                                    type: 'navigation',
                                    priority: 1
                                });
                            }
                        });
                    } catch (e) {
                        console.log('Selector error:', selector, e.message);
                    }
                });

                // 일반 내부 링크 수집 (제한적으로)
                const internalLinks = document.querySelectorAll('a[href]');
                let linkCount = 0;
                internalLinks.forEach(link => {
                    if (linkCount >= 50) return; // 최대 50개로 제한

                    if (link.href &&
                        link.href.includes(window.location.origin) &&
                        !link.href.includes('#') &&
                        !link.href.includes('javascript:') &&
                        !visitedUrls.has(link.href) &&
                        linkCount < 50) {
                        visitedUrls.add(link.href);
                        links.push({
                            text: link.textContent.trim(),
                            url: link.href,
                            type: 'internal',
                            priority: 2
                        });
                        linkCount++;
                    }
                });

                // 우선순위별 정렬 및 중복 제거
                return links
                    .filter((link, index, self) =>
                        self.findIndex(l => l.url === link.url) === index)
                    .sort((a, b) => a.priority - b.priority)
                    .slice(0, MAX_PAGES);

            } catch (e) {
                console.error('Link collection error:', e.message);
                return [];
            }
        }
        """)

        return all_links or []
    except Exception as e:
        print(f"링크 수집 실패: {str(e)}")
        return []

async def safe_login(username: str, password: str) -> bool:
    """안전한 로그인 처리"""
    try:
        # 로그인 폼 찾기
        login_result = await mcp__chrome_devtools__evaluate_script("""
        () => {
            try {
                const forms = document.querySelectorAll('form');
                for (let form of forms) {
                    const passwordInputs = form.querySelectorAll('input[type="password"], input[name*="password"], input[name*="pass"]');
                    if (passwordInputs.length > 0) {
                        const passwordField = passwordInputs[0];
                        let usernameField = form.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="id"], input[name*="username"]');

                        return {
                            formAction: form.action || form.querySelector('button[type="submit"]')?.form?.action || '',
                            passwordField: passwordField.name || passwordField.id,
                            usernameField: usernameField?.name || usernameField?.id || '',
                            submitButton: form.querySelector('button[type="submit"], input[type="submit"]')?.id || ''
                        };
                    }
                }
                return null;
            } catch (e) {
                console.error('Login form detection error:', e.message);
                return null;
            }
        }
        """)

        if not login_result or not login_result.get('usernameField'):
            print("로그인 폼을 찾을 수 없습니다.")
            return False

        # 로그인 정보 입력
        await mcp__chrome_devtools__fill_form([
            {"uid": login_result['usernameField'], "value": username},
            {"uid": login_result['passwordField'], "value": password}
        ])

        # 로그인 버튼 클릭
        if login_result.get('submitButton'):
            await mcp__chrome_devtools__click(login_result['submitButton'])
        else:
            # 엔터키 전송
            await mcp__chrome_devtools__evaluate_script(f"""
            () => {{
                try {{
                    const submitBtn = document.querySelector('button[type="submit"], input[type="submit"]');
                    if (submitBtn) submitBtn.click();
                }} catch (e) {{
                    console.log('Submit error:', e.message);
                }}
            }}
            """)

        await asyncio.sleep(3)  # 로그인 처리 대기
        return True

    except Exception as e:
        print(f"로그인 처리 실패: {str(e)}")
        return False

# 메인 분석 프로세스
async def analyze_website(target_url: str, username: Optional[str] = None, password: Optional[str] = None):
    """웹사이트 분석 메인 함수"""

    # 1. 초기 페이지 접속
    if not await safe_navigate(target_url):
        raise Exception(f"초기 페이지 접속 실패: {target_url}")

    # 2. 로그인 처리 (필요시)
    if username and password:
        print("로그인을 시도합니다...")
        if not await safe_login(username, password):
            print("로그인에 실패했습니다. 비인증 상태로 분석을 계속합니다.")

    # 3. 링크 수집
    print("웹사이트 링크를 수집합니다...")
    all_links = await collect_links_safely()
    print(f"총 {len(all_links)}개의 링크를 발견했습니다.")

    # 4. 각 페이지 분석 (병렬 처리 방지로 안정성 확보)
    menu_analysis = []
    processed_urls = set()

    for i, link in enumerate(all_links):
        url = link['url']

        # 중복 URL 건너뛰기
        if url in processed_urls:
            continue
        processed_urls.add(url)

        print(f"페이지 분석 중 ({i+1}/{len(all_links)}): {url}")

        # 안전한 페이지 이동
        if await safe_navigate(url):
            try:
                # 페이지 분석
                page_analysis = await analyze_page_security(url, link['text'])
                if page_analysis:
                    menu_analysis.append(page_analysis)

                # 분석 간 짧은 대기 (과부하 방지)
                await asyncio.sleep(1)

            except Exception as e:
                print(f"페이지 분석 실패: {url} - {str(e)}")
                continue
        else:
            print(f"페이지 접속 실패: {url}")
            continue

    return menu_analysis

# 실행
try:
    menu_analysis = await analyze_website(target_url, username, password)
    print(f"분석 완료: 총 {len(menu_analysis)}개 페이지 분석됨")
except Exception as e:
    print(f"분석 중 치명적 오류 발생: {str(e)}")
    # 부분 결과라도 저장
    menu_analysis = menu_analysis if 'menu_analysis' in locals() else []
```

### 4. 페이지별 상세 보안 분석

각 페이지에 대해 종합적인 보안 분석을 수행한다:

```python
async def analyze_page_security(url: str, menu_text: str) -> Optional[Dict[str, Any]]:
    """안전한 페이지 보안 분석"""
    try:
        # 1. 페이지 상태 확인
        page_status = await mcp__chrome_devtools__evaluate_script("""
        () => {
            try {
                return {
                    readyState: document.readyState,
                    title: document.title,
                    hasError: document.querySelector('.error, .error-message') !== null
                };
            } catch (e) {
                return { error: e.message };
            }
        }
        """)

        if not page_status or page_status.get('error'):
            print(f"페이지 상태 확인 실패: {url}")
            return None

        # 2. 네트워크 요청 수집
        try:
            network_requests = await mcp__chrome_devtools__list_network_requests(
                pageSize=50, includePreservedRequests=True
            )
        except Exception as e:
            print(f"네트워크 요청 수집 실패: {str(e)}")
            network_requests = []

        # 3. 폼 요소 분석
        forms = []
        try:
            forms = await mcp__chrome_devtools__evaluate_script("""
            () => {
                try {
                    const forms = [];
                    document.querySelectorAll('form').forEach((form, index) => {
                        const formData = {
                            index: index,
                            action: form.action || '',
                            method: (form.method || 'GET').toUpperCase(),
                            id: form.id || '',
                            className: form.className || '',
                            inputs: []
                        };

                        // 입력 필드 수집
                        form.querySelectorAll('input, select, textarea').forEach(input => {
                            const inputType = input.type || input.tagName.toLowerCase();
                            formData.inputs.push({
                                name: input.name || input.id || '',
                                type: inputType,
                                required: input.required || false,
                                placeholder: input.placeholder || '',
                                value: input.value || '',
                                id: input.id || '',
                                className: input.className || '',
                                hasValidation: input.pattern || input.maxLength || input.minLength
                            });
                        });

                        forms.push(formData);
                    });
                    return forms;
                } catch (e) {
                    console.error('Form analysis error:', e.message);
                    return [];
                }
            }
            """)
        except Exception as e:
            print(f"폼 분석 실패: {str(e)}")

        # 4. API 엔드포인트 분석
        api_endpoints = []
        try:
            api_endpoints = await mcp__chrome_devtools__evaluate_script("""
            () => {
                try {
                    const endpoints = [];
                    const scripts = document.querySelectorAll('script');

                    scripts.forEach(script => {
                        if (script.textContent) {
                            const content = script.textContent;

                            // fetch 호출 패턴 (더 정확한 정규식)
                            const fetchRegex = /fetch\\s*\\(\\s*['"`]([^'"`]+)['"`]\\s*,?[^)]*\\)/g;
                            let match;
                            while ((match = fetchRegex.exec(content)) !== null) {
                                const url = match[1];
                                if (url.startsWith('/') || url.includes(window.location.hostname)) {
                                    endpoints.push({
                                        url: url,
                                        method: 'FETCH',
                                        source: 'javascript',
                                        context: 'fetch_call'
                                    });
                                }
                            }

                            // XMLHttpRequest 패턴
                            const xhrRegex = /\\.open\\s*\\(\\s*['"`]([A-Z]+)['"`]\\s*,\\s*['"`]([^'"`]+)['"`]/g;
                            while ((match = xhrRegex.exec(content)) !== null) {
                                const method = match[1];
                                const url = match[2];
                                if (url.startsWith('/') || url.includes(window.location.hostname)) {
                                    endpoints.push({
                                        url: url,
                                        method: method,
                                        source: 'javascript',
                                        context: 'xhr_call'
                                    });
                                }
                            }
                        }
                    });

                    return [...new Set(endpoints.map(e => JSON.stringify(e)))].map(e => JSON.parse(e));
                } catch (e) {
                    console.error('API endpoint analysis error:', e.message);
                    return [];
                }
            }
            """)
        except Exception as e:
            print(f"API 엔드포인트 분석 실패: {str(e)}")

        # 5. 취약점 패턴 분석
        vulnerabilities = []
        try:
            vulnerabilities = await analyze_vulnerability_patterns_safe(url, forms)
        except Exception as e:
            print(f"취약점 분석 실패: {str(e)}")

        # 6. 보안 헤더 및 상태 분석
        security_headers = {}
        try:
            security_headers = await mcp__chrome_devtools__evaluate_script("""
            () => {
                try {
                    return {
                        cookies: document.cookie || '',
                        https: window.location.protocol === 'https:',
                        domain: window.location.hostname,
                        cspMeta: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content || '',
                        hasMixedContent: document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]').length > 0,
                        localStorageKeys: Object.keys(localStorage).length,
                        sessionStorageKeys: Object.keys(sessionStorage).length
                    };
                } catch (e) {
                    console.error('Security header analysis error:', e.message);
                    return { error: e.message };
                }
            }
            """)
        except Exception as e:
            print(f"보안 헤더 분석 실패: {str(e)}")

        # 7. 결과 정리 및 중복 제거
        return {
            'menu': menu_text or '알 수 없는 메뉴',
            'url': url,
            'forms': forms or [],
            'api_endpoints': api_endpoints or [],
            'vulnerabilities': vulnerabilities or [],
            'security_headers': security_headers or {},
            'network_request_count': len(network_requests) if network_requests else 0,
            'analysis_timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        print(f"페이지 분석 중 오류 발생: {url} - {str(e)}")
        return None
```

### 5. 취약점 패턴 분석 (공격 없음)

XSS, SQL Injection 등 다양한 취약점 패턴을 분석한다:

```python
async def analyze_vulnerability_patterns_safe(url: str, forms: List[Dict]) -> List[Dict[str, Any]]:
    """안전한 취약점 패턴 분석"""
    try:
        vulnerabilities = await mcp__chrome_devtools__evaluate_script("""
        (forms) => {
            try {
                const vulnerabilities = [];
                const seenPatterns = new Set();

                // XSS 취약점 패턴 분석 (개선된 정확성)
                const inputs = document.querySelectorAll('input, textarea');
                const scripts = document.querySelectorAll('script');

                inputs.forEach(input => {
                    const inputName = input.name || input.id || 'unnamed';
                    const inputType = input.type || 'text';

                    // 1. dangerouslySetInnerHTML 사용 확인
                    scripts.forEach(script => {
                        if (script.textContent) {
                            const content = script.textContent;

                            // React dangerouslySetInnerHTML
                            if (content.includes('dangerouslySetInnerHTML') &&
                                content.includes(inputName)) {
                                const patternId = `dangerous_innerhtml_${inputName}`;
                                if (!seenPatterns.has(patternId)) {
                                    seenPatterns.add(patternId);
                                    vulnerabilities.push({
                                        type: 'XSS',
                                        severity: 'HIGH',
                                        element: inputName,
                                        elementType: 'input',
                                        description: 'React dangerouslySetInnerHTML 사용으로 DOM 기반 XSS 가능성',
                                        pattern: 'dangerous_innerhtml_usage',
                                        confidence: 'HIGH'
                                    });
                                }
                            }

                            // 직접 innerHTML 사용
                            if (content.includes('innerHTML') &&
                                (content.includes(inputName) || content.includes(input.id))) {
                                const patternId = `innerhtml_${inputName}`;
                                if (!seenPatterns.has(patternId)) {
                                    seenPatterns.add(patternId);
                                    vulnerabilities.push({
                                        type: 'XSS',
                                        severity: 'MEDIUM',
                                        element: inputName,
                                        elementType: 'input',
                                        description: '직접 innerHTML 사용으로 XSS 가능성',
                                        pattern: 'direct_innerhtml_usage',
                                        confidence: 'MEDIUM'
                                    });
                                }
                            }
                        }
                    });

                    // 2. 입력 검증 부재 확인
                    const hasPattern = input.pattern || '';
                    const hasMaxLength = input.maxLength && input.maxLength > 0;
                    const hasMinLength = input.minLength && input.minLength > 0;
                    const isSensitiveType = ['text', 'search', 'url', 'email'].includes(inputType);

                    if (!hasPattern && !hasMaxLength && !hasMinLength &&
                        inputType !== 'hidden' && inputType !== 'password' && isSensitiveType) {
                        const patternId = `no_validation_${inputName}`;
                        if (!seenPatterns.has(patternId)) {
                            seenPatterns.add(patternId);
                            vulnerabilities.push({
                                type: 'XSS',
                                severity: 'LOW',
                                element: inputName,
                                elementType: 'input',
                                description: '입력값 검증 부재로 XSS 가능성',
                                pattern: 'input_validation_missing',
                                confidence: 'LOW'
                            });
                        }
                    }
                });

                // SQL Injection 패턴 분석 (개선된 정확성)
                scripts.forEach(script => {
                    if (script.textContent) {
                        const content = script.textContent;

                        // 1. 문자열 연결을 통한 동적 쿼리 생성
                        const stringConcatPatterns = [
                            /['"`]s*\\+\\s*['"`]/g,  // ' + ' 또는 " + " 또는 ` + `
                            /\\$\\{[^}]*\\}/g,      // 템플릿 리터럴
                            /String\\.prototype\\.concat/g  // String.prototype.concat
                        ];

                        stringConcatPatterns.forEach(pattern => {
                            if (pattern.test(content)) {
                                const patternId = 'string_concatenation';
                                if (!seenPatterns.has(patternId)) {
                                    seenPatterns.add(patternId);
                                    vulnerabilities.push({
                                        type: 'SQL_INJECTION',
                                        severity: 'HIGH',
                                        element: 'JavaScript_Code',
                                        elementType: 'script',
                                        description: '문자열 연결을 통한 동적 쿼리 생성 패턴',
                                        pattern: 'string_concatenation_query',
                                        confidence: 'HIGH'
                                    });
                                }
                            }
                        });

                        // 2. 파라미터 직접 사용 (더 정확한 패턴)
                        const parameterPatterns = [
                            /req\\.body\\s*\\+\\s*['"`]/g,
                            /req\\.params\\s*\\+\\s*['"`]/g,
                            /req\\.query\\s*\\+\\s*['"`]/g,
                            /query\\s*\\+\\s*['"`]([^'"`]*req\\.)/g
                        ];

                        parameterPatterns.forEach(pattern => {
                            if (pattern.test(content)) {
                                const patternId = 'direct_parameter_usage';
                                if (!seenPatterns.has(patternId)) {
                                    seenPatterns.add(patternId);
                                    vulnerabilities.push({
                                        type: 'SQL_INJECTION',
                                        severity: 'HIGH',
                                        element: 'JavaScript_Code',
                                        elementType: 'script',
                                        description: '요청 파라미터를 직접 쿼리에 사용하는 패턴',
                                        pattern: 'direct_parameter_query',
                                        confidence: 'HIGH'
                                    });
                                }
                            }
                        });
                    }
                });

                // CSRF 취약점 패턴 (개선된 검증)
                const forms = document.querySelectorAll('form');
                forms.forEach(form => {
                    const method = (form.method || 'GET').toLowerCase();
                    const action = form.action || '';

                    if (method === 'post' && action) {
                        // 다양한 CSRF 토큰 패턴 확인
                        const csrfSelectors = [
                            'input[name*="token"]',
                            'input[name*="csrf"]',
                            'input[name*="_token"]',
                            'input[name*="anti-forgery"]',
                            'input[name*="authenticity"]'
                        ];

                        let hasToken = false;
                        for (const selector of csrfSelectors) {
                            if (form.querySelector(selector)) {
                                hasToken = true;
                                break;
                            }
                        }

                        if (!hasToken) {
                            const formId = form.id || form.className || `form_${action}`;
                            const patternId = `missing_csrf_${formId}`;
                            if (!seenPatterns.has(patternId)) {
                                seenPatterns.add(patternId);
                                vulnerabilities.push({
                                    type: 'CSRF',
                                    severity: 'MEDIUM',
                                    element: action,
                                    elementType: 'form',
                                    description: 'CSRF 토큰 부재',
                                    pattern: 'missing_csrf_token',
                                    confidence: 'MEDIUM'
                                });
                            }
                        }
                    }
                });

                // 인증/권한 관련 취약점
                const adminSelectors = [
                    '.admin', '#admin', '.admin-panel', '.dashboard',
                    '[class*="admin"]', '[id*="admin"]'
                ];

                adminSelectors.forEach(selector => {
                    if (document.querySelector(selector)) {
                        const patternId = 'admin_structure_exposure';
                        if (!seenPatterns.has(patternId)) {
                            seenPatterns.add(patternId);
                            vulnerabilities.push({
                                type: 'AUTHORIZATION',
                                severity: 'MEDIUM',
                                element: 'Page_Structure',
                                elementType: 'dom',
                                description: '관리자 페이지 구조 노출',
                                pattern: 'admin_structure_exposure',
                                confidence: 'MEDIUM'
                            });
                        }
                    }
                });

                // 정보노출 관련 취약점
                const errorSelectors = [
                    '.error', '.alert-danger', '[class*="error"]',
                    '.stack-trace', '.exception', '[class*="exception"]'
                ];

                errorSelectors.forEach(selector => {
                    const elements = document.querySelectorAll(selector);
                    elements.forEach(element => {
                        const text = element.textContent || '';
                        const sensitiveKeywords = [
                            'sql', 'database', 'stack trace', 'exception',
                            'internal server error', 'fatal error', 'debug'
                        ];

                        if (sensitiveKeywords.some(keyword => text.toLowerCase().includes(keyword))) {
                            const patternId = 'information_disclosure';
                            if (!seenPatterns.has(patternId)) {
                                seenPatterns.add(patternId);
                                vulnerabilities.push({
                                    type: 'INFORMATION_DISCLOSURE',
                                    severity: 'HIGH',
                                    element: 'Error_Message',
                                    elementType: 'dom',
                                    description: '상세 에러 메시지 노출',
                                    pattern: 'detailed_error_exposure',
                                    confidence: 'HIGH'
                                });
                            }
                        }
                    });
                });

                // 보안 헤더 관련 취약점 (더 포괄적인 검사)
                const securityHeaders = [
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'X-XSS-Protection',
                    'Strict-Transport-Security',
                    'Content-Security-Policy'
                ];

                securityHeaders.forEach(header => {
                    const metaSelector = `meta[http-equiv="${header}"]`;
                    if (!document.querySelector(metaSelector) && !document.querySelector(`meta[http-equiv*="${header.toLowerCase()}"]`)) {
                        const patternId = `missing_${header}`;
                        if (!seenPatterns.has(patternId)) {
                            seenPatterns.add(patternId);
                            vulnerabilities.push({
                                type: 'SECURITY_HEADERS',
                                severity: 'LOW',
                                element: 'HTTP_Headers',
                                elementType: 'headers',
                                description: `${header} 헤더 부재`,
                                pattern: 'missing_security_headers',
                                confidence: 'LOW'
                            });
                        }
                    }
                });

                return vulnerabilities;
            } catch (e) {
                console.error('Vulnerability analysis error:', e.message);
                return [];
            }
        }
        """, forms)

        return vulnerabilities or []
    except Exception as e:
        print(f"취약점 패턴 분석 실패: {str(e)}")
        return []
```

### 6. 엑셀 보고서 생성 (개선된 정확성)

분석 결과를 중복 제거하고 정확도를 높여 메뉴별 컬럼 형태의 엑셀 보고서로 생성한다:

```python
import sys
import os
from datetime import datetime, timezone
from typing import List, Dict, Any
import pandas as pd
import chardet

sys.path.append(os.path.join(os.path.dirname(__file__), 'xlsx', 'scripts'))
from excel_generator import ExcelReportGenerator

def detect_file_encoding(file_path: str) -> str:
    """파일 인코딩 자동 감지"""
    try:
        with open(file_path, 'rb') as f:
            result = chardet.detect(f.read(10000))  # 앞 10KB만 읽어서 감지
        detected_encoding = result.get('encoding', 'utf-8')
        confidence = result.get('confidence', 0)

        print(f"감지된 인코딩: {detected_encoding} (신뢰도: {confidence:.2f})")

        # 신뢰도가 낮거나 감지 실패 시 일반적인 한글 인코딩 시도
        if confidence < 0.7 or not detected_encoding:
            for encoding in ['utf-8', 'cp949', 'euc-kr', 'utf-8-sig']:
                try:
                    with open(file_path, 'r', encoding=encoding) as test_file:
                        test_file.read(1000)  # 일단 읽어보기
                    print(f"성공적인 인코딩: {encoding}")
                    return encoding
                except (UnicodeDecodeError, LookupError):
                    continue

        return detected_encoding if detected_encoding else 'utf-8'
    except Exception as e:
        print(f"인코딩 감지 실패: {str(e)}, 기본값 utf-8 사용")
        return 'utf-8'

def safe_read_csv(file_path: str) -> pd.DataFrame:
    """안전한 CSV 파일 읽기 (인코딩 자동 감지)"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"CSV 파일을 찾을 수 없습니다: {file_path}")

    # 인코딩 감지
    encoding = detect_file_encoding(file_path)

    # 여러 인코딩으로 시도
    encodings_to_try = [encoding, 'utf-8', 'utf-8-sig', 'cp949', 'euc-kr', 'latin-1']

    for enc in encodings_to_try:
        try:
            print(f"CSV 읽기 시도 (인코딩: {enc}): {file_path}")
            df = pd.read_csv(file_path, encoding=enc)
            print(f"CSV 파일 성공적으로 읽음: {len(df)}개 행, 인코딩: {enc}")
            return df
        except (UnicodeDecodeError, LookupError) as e:
            print(f"인코딩 {enc} 실패: {str(e)}")
            continue
        except Exception as e:
            print(f"CSV 읽기 중 오류 (인코딩: {enc}): {str(e)}")
            continue

    raise Exception(f"CSV 파일을 어떤 인코딩으로도 읽을 수 없습니다: {file_path}")

# CSV 파일 읽기 예시 (필요시 사용)
# def load_csv_data(csv_file_path: str) -> pd.DataFrame:
#     """CSV 파일을 안전하게 읽어서 분석 데이터로 변환"""
#     try:
#         df = safe_read_csv(csv_file_path)
#
#         # 필요한 컬럼이 있는지 확인
#         required_columns = ['menu', 'url', 'vulnerability_type', 'severity']
#         missing_columns = [col for col in required_columns if col not in df.columns]
#
#         if missing_columns:
#             print(f"경고: 필요한 컬럼이 없습니다: {missing_columns}")
#             print(f"사용 가능한 컬럼: {list(df.columns)}")
#
#         return df
#     except Exception as e:
#         print(f"CSV 파일 로드 실패: {str(e)}")
#         return pd.DataFrame()

def process_analysis_results(menu_analysis: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """분석 결과를 전처리하고 중복을 제거"""
    excel_data = []
    seen_entries = set()  # 중복 방지용

    for analysis in menu_analysis:
        if not analysis:
            continue

        menu = analysis.get('menu', '알 수 없는 메뉴')
        url = analysis.get('url', '')
        security_headers = analysis.get('security_headers', {})
        is_https = security_headers.get('https', False)

        # 1. 폼 분석 결과 처리
        forms = analysis.get('forms', [])
        for form in forms:
            if not form:
                continue

            form_action = form.get('action', '') or form.get('id', '') or 'unknown_form'
            form_method = form.get('method', 'GET').upper()
            inputs = form.get('inputs', [])

            # 파라미터 정보 생성
            if inputs:
                param_list = []
                for inp in inputs:
                    param_name = inp.get('name', '') or inp.get('id', '')
                    param_type = inp.get('type', 'unknown')
                    if param_name:
                        param_list.append(f"{param_name}({param_type})")
                parameters = ', '.join(param_list) if param_list else 'No parameters'
            else:
                parameters = 'No input fields'

            # 폼에 대한 기본 정보 행 (취약점이 없는 경우도 포함)
            form_base_key = f"{url}_{form_action}_{form_method}"
            if form_base_key not in seen_entries:
                seen_entries.add(form_base_key)
                excel_data.append({
                    '메뉴': menu,
                    'URL': url,
                    '요소유형': 'FORM',
                    '요소명': f"{form_action}",
                    '파라미터': parameters,
                    'HTTP메소드': form_method,
                    '취약점종류': '없음',
                    '위험도': 'LOW',
                    '상세설명': '특별한 취약점이 발견되지 않음',
                    '패턴': '-',
                    '인증필요': 'Yes' if is_https else 'No',
                    '권장조치': '정기적인 보안 점검 권장'
                })

        # 2. API 엔드포인트 분석 결과 처리
        api_endpoints = analysis.get('api_endpoints', [])
        for api in api_endpoints:
            if not api:
                continue

            api_url = api.get('url', '')
            api_method = api.get('method', 'GET')

            # API에 대한 기본 정보 행
            api_base_key = f"{url}_{api_url}_{api_method}"
            if api_base_key not in seen_entries:
                seen_entries.add(api_base_key)
                excel_data.append({
                    '메뉴': menu,
                    'URL': url,
                    '요소유형': 'API',
                    '요소명': api_url,
                    '파라미터': 'API_Endpoint',
                    'HTTP메소드': api_method,
                    '취약점종류': 'API_ENDPOINT',
                    '위험도': 'LOW',
                    '상세설명': f'API 엔드포인트 발견: {api_url}',
                    '패턴': 'api_endpoint',
                    '인증필요': 'Yes' if is_https else 'No',
                    '권장조치': 'API 인증 및 접근 제어 검토 필요'
                })

        # 3. 취약점 분석 결과 처리 (중복 방지)
        vulnerabilities = analysis.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if not vuln:
                continue

            vuln_type = vuln.get('type', '')
            vuln_severity = vuln.get('severity', 'MEDIUM')
            vuln_element = vuln.get('element', '')
            vuln_pattern = vuln.get('pattern', '')
            vuln_description = vuln.get('description', '')

            # 취약점에 대한 상세 행 생성
            vuln_key = f"{url}_{vuln_type}_{vuln_element}_{vuln_pattern}"
            if vuln_key not in seen_entries:
                seen_entries.add(vuln_key)

                # 요소유형 결정
                element_type = 'OTHER'
                if vuln_element and vuln_element != 'JavaScript_Code':
                    element_type = 'FORM'
                elif vuln_element == 'JavaScript_Code':
                    element_type = 'SCRIPT'

                excel_data.append({
                    '메뉴': menu,
                    'URL': url,
                    '요소유형': element_type,
                    '요소명': vuln_element,
                    '파라미터': _get_param_for_vulnerability(vuln_element, forms, api_endpoints),
                    'HTTP메소드': _get_method_for_vulnerability(vuln_element, forms, api_endpoints),
                    '취약점종류': vuln_type,
                    '위험도': vuln_severity,
                    '상세설명': vuln_description,
                    '패턴': vuln_pattern,
                    '인증필요': 'Yes' if is_https else 'No',
                    '권장조치': _get_enhanced_recommendation(vuln_type, vuln_severity, vuln_pattern)
                })

    # 결과 정렬 (위험도 순)
    severity_order = {'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    excel_data.sort(key=lambda x: (
        severity_order.get(x.get('위험도', 'LOW'), 3),
        x.get('메뉴', ''),
        x.get('URL', '')
    ))

    return excel_data

def _get_param_for_vulnerability(element: str, forms: List[Dict], apis: List[Dict]) -> str:
    """취약점에 해당하는 파라미터 정보 반환"""
    if not element:
        return 'Unknown'

    # 폼 요소 찾기
    for form in forms:
        form_action = form.get('action', '') or form.get('id', '')
        if element == form_action or element in form.get('action', ''):
            inputs = form.get('inputs', [])
            param_list = []
            for inp in inputs:
                param_name = inp.get('name', '') or inp.get('id', '')
                param_type = inp.get('type', 'unknown')
                if param_name:
                    param_list.append(f"{param_name}({param_type})")
            return ', '.join(param_list) if param_list else 'No parameters'

    # API 요소 찾기
    for api in apis:
        if element == api.get('url', ''):
            return 'API_Parameters'

    return 'Unknown'

def _get_method_for_vulnerability(element: str, forms: List[Dict], apis: List[Dict]) -> str:
    """취약점에 해당하는 HTTP 메소드 반환"""
    if not element:
        return 'UNKNOWN'

    # 폼 요소 찾기
    for form in forms:
        form_action = form.get('action', '') or form.get('id', '')
        if element == form_action or element in form.get('action', ''):
            return form.get('method', 'GET').upper()

    # API 요소 찾기
    for api in apis:
        if element == api.get('url', ''):
            return api.get('method', 'GET')

    return 'UNKNOWN'

def _get_enhanced_recommendation(vuln_type: str, severity: str, pattern: str) -> str:
    """취약점 타입과 심각도에 따른 상세 권장 조치"""
    base_recommendations = {
        'XSS': '입력값 검증 및 출력값 인코딩 적용',
        'SQL_INJECTION': 'Prepare Statement 또는 Parameterized Query 사용',
        'CSRF': 'CSRF 토큰 구현 및 검증',
        'AUTHORIZATION': '적절한 인증 및 권한 체계 구현',
        'INFORMATION_DISCLOSURE': '일반화된 에러 메시지 사용',
        'SECURITY_HEADERS': '보안 관련 HTTP 헤더 설정'
    }

    base_rec = base_recommendations.get(vuln_type, '상세한 보안 검토 필요')

    # 심각도에 따른 추가 권장사항
    if severity == 'HIGH':
        return f"[긴급] {base_rec} - 즉시 조치 필요"
    elif severity == 'MEDIUM':
        return f"[권고] {base_rec} - 조속 조치 권장"
    else:
        return f"[권장] {base_rec}"

def create_markdown_report(data: List[Dict[str, str]], output_file: str, target_url: str, analysis_time: datetime) -> None:
    """마크다운 보고서 생성 (한국 시간 기준)"""
    try:
        # 분석 시간을 한국 시간으로 포맷
        report_date = analysis_time.strftime('%Y년 %m월 %d일 %H:%M:%S')

        # 통계 계산
        total_items = len(data)
        severity_stats = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        vuln_types = {}
        menu_stats = {}

        for item in data:
            severity = item.get('위험도', 'LOW')
            severity_stats[severity] = severity_stats.get(severity, 0) + 1

            vuln_type = item.get('취약점종류', '')
            if vuln_type and vuln_type != '없음':
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

            menu = item.get('메뉴', '')
            menu_stats[menu] = menu_stats.get(menu, 0) + 1

        # 마크다운 내용 생성
        content = f"""# 웹사이트 보안 분석 보고서

## 기본 정보

| 항목 | 내용 |
|------|------|
| 분석 대상 | {target_url} |
| 분석 일자 | {report_date} |
| 총 분석 항목 | {total_items}개 |
| 분석 방식 | Chrome DevTools + 패턴 분석 (공격 없음) |

## 분석 결과 요약

### 위험도별 분포

| 위험도 | 개수 | 비율 |
|--------|------|------|
| 🔴 HIGH | {severity_stats.get('HIGH', 0)}개 | {severity_stats.get('HIGH', 0)/total_items*100:.1f}% |
| 🟡 MEDIUM | {severity_stats.get('MEDIUM', 0)}개 | {severity_stats.get('MEDIUM', 0)/total_items*100:.1f}% |
| 🟢 LOW | {severity_stats.get('LOW', 0)}개 | {severity_stats.get('LOW', 0)/total_items*100:.1f}% |

### 취약점 종류별 분포

"""

        # 취약점 종류별 테이블 추가
        if vuln_types:
            content += "| 취약점 종류 | 개수 |\n|-------------|------|\n"
            for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                content += f"| {vuln_type} | {count}개 |\n"
            content += "\n"

        # 상세 분석 결과
        content += "## 상세 분석 결과\n\n"

        if not data:
            content += "분석된 데이터가 없습니다.\n"
        else:
            # 위험도별 그룹화
            high_items = [item for item in data if item.get('위험도') == 'HIGH']
            medium_items = [item for item in data if item.get('위험도') == 'MEDIUM']
            low_items = [item for item in data if item.get('위험도') == 'LOW']

            # HIGH 위험도 항목
            if high_items:
                content += "### 🔴 HIGH 위험도 취약점\n\n"
                for item in high_items:
                    content += f"**{item.get('메뉴', '알 수 없음')}** - `{item.get('URL', '')}`\n\n"
                    content += f"- **요소유형**: {item.get('요소유형', '')}\n"
                    content += f"- **요소명**: {item.get('요소명', '')}\n"
                    content += f"- **취약점종류**: {item.get('취약점종류', '')}\n"
                    content += f"- **상세설명**: {item.get('상세설명', '')}\n"
                    content += f"- **패턴**: `{item.get('패턴', '')}`\n"
                    content += f"- **권장조치**: {item.get('권장조치', '')}\n\n"
                    content += "---\n\n"

            # MEDIUM 위험도 항목
            if medium_items:
                content += "### 🟡 MEDIUM 위험도 취약점\n\n"
                for item in medium_items:
                    content += f"**{item.get('메뉴', '알 수 없음')}** - `{item.get('URL', '')}`\n\n"
                    content += f"- **요소유형**: {item.get('요소유형', '')}\n"
                    content += f"- **요소명**: {item.get('요소명', '')}\n"
                    content += f"- **취약점종류**: {item.get('취약점종류', '')}\n"
                    content += f"- **상세설명**: {item.get('상세설명', '')}\n"
                    content += f"- **패턴**: `{item.get('패턴', '')}`\n"
                    content += f"- **권장조치**: {item.get('권장조치', '')}\n\n"
                    content += "---\n\n"

            # LOW 위험도 항목 (주요 내용만)
            if low_items:
                content += "### 🟢 LOW 위험도 및 일반 항목\n\n"
                low_by_menu = {}
                for item in low_items:
                    menu = item.get('메뉴', '알 수 없음')
                    if menu not in low_by_menu:
                        low_by_menu[menu] = []
                    low_by_menu[menu].append(item)

                for menu, items in low_by_menu.items():
                    content += f"**{menu}**\n\n"
                    for item in items:
                        vuln_type = item.get('취약점종류', '')
                        element = item.get('요소명', '')
                        description = item.get('상세설명', '')

                        if vuln_type != '없음':
                            content += f"- {vuln_type}: {description} ({element})\n"
                        else:
                            content += f"- 정상: {description}\n"
                    content += "\n"

        # 권장 조치 요약
        content += """## 권장 조치 요약

### 즉시 조치 필요 (HIGH 위험도)
"""
        if severity_stats.get('HIGH', 0) > 0:
            high_items = [item for item in data if item.get('위험도') == 'HIGH']
            unique_recommendations = set()
            for item in high_items:
                rec = item.get('권장조치', '')
                if rec:
                    unique_recommendations.add(rec)

            for i, rec in enumerate(unique_recommendations, 1):
                content += f"{i}. {rec}\n"
        else:
            content += "HIGH 위험도 취약점이 발견되지 않았습니다.\n"

        content += """
### 조속 조치 권장 (MEDIUM 위험도)
"""
        if severity_stats.get('MEDIUM', 0) > 0:
            medium_items = [item for item in data if item.get('위험도') == 'MEDIUM']
            unique_recommendations = set()
            for item in medium_items:
                rec = item.get('권장조치', '')
                if rec:
                    unique_recommendations.add(rec)

            for i, rec in enumerate(unique_recommendations, 1):
                content += f"{i}. {rec}\n"
        else:
            content += "MEDIUM 위험도 취약점이 발견되지 않았습니다.\n"

        content += f"""
## 분석 메타 정보

- **분석 도구**: Chrome DevTools + 자동화 스크립트
- **분석 방식**: 공격 없는 코드 패턴 분석
- **분석 시각**: {report_date}
- **총 분석 시간**: 자동 수집 및 분석
- **보고서 생성**: 자동화된 보고서 생성 시스템

## 중요 참고사항

⚠️ **본 보고서는 자동화된 코드 패턴 분석을 기반으로 합니다.**
- 실제 공격을 수행하지 않았으며, 발견된 패턴은 취약점 가능성을 나타냅니다.
- 모든 HIGH 및 MEDIUM 위험도 항목은 보안 전문가의 추가 검토가 필요합니다.
- 오탐(false positive) 가능성이 있으므로 수동 검증이 권장됩니다.
- 정기적인 재분석을 통해 새로운 취약점 발생을 모니터링해야 합니다.

---
*보고서 생성 시간: {report_date}*
"""

        # 파일 저장 (UTF-8 인코딩)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)

    except Exception as e:
        print(f"마크다운 보고서 생성 실패: {str(e)}")
        # 오류 시 기본 보고서 생성
        try:
            error_content = f"""# 웹사이트 보안 분석 보고서 (오류)

## 기본 정보

- 분석 대상: {target_url}
- 분석 일자: {report_date}
- 상태: 보고서 생성 중 오류 발생

## 오류 정보

{str(e)}

## 권장 조치

시스템 관리자에게 문의하여 정상적인 보고서 생성을 확인하세요.
"""
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(error_content)
        except Exception as fallback_error:
            print(f"오류 보고서 생성 실패: {str(fallback_error)}")

# 엑셀 보고서 생성
try:
    print("분석 결과를 처리합니다...")
    processed_data = process_analysis_results(menu_analysis)
    print(f"총 {len(processed_data)}개의 분석 항목을 생성했습니다.")

    # 엑셀 보고서 생성 (현재 작업 디렉토리에 생성)
    # 현재 한국 시간으로 날짜 생성
    kst = datetime.now(timezone('Asia/Seoul'))
    timestamp = kst.strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(os.getcwd(), f'website_security_analysis_{timestamp}.xlsx')

    generator = ExcelReportGenerator(processed_data)
    generator.create_detailed_report(output_file)

    print(f"엑셀 보고서 생성 완료: {output_file}")

    # 마크다운 보고서 생성 (한국 시간 기준)
    markdown_file = os.path.join(os.getcwd(), f'website_security_analysis_{timestamp}.md')
    create_markdown_report(processed_data, markdown_file, target_url, kst)
    print(f"마크다운 보고서 생성 완료: {markdown_file}")

except Exception as e:
    print(f"보고서 생성 중 오류 발생: {str(e)}")
    # 기본 보고서 생성 시도
    try:
        fallback_data = [{
            '메뉴': '분석 오류',
            'URL': target_url,
            '요소유형': 'ERROR',
            '요소명': 'analysis_failed',
            '파라미터': 'error',
            'HTTP메소드': 'UNKNOWN',
            '취약점종류': 'SYSTEM_ERROR',
            '위험도': 'HIGH',
            '상세설명': f'분석 과정에서 오류 발생: {str(e)}',
            '패턴': 'analysis_error',
            '인증필요': 'Unknown',
            '권장조치': '시스템 관리자에게 문의'
        }]

        output_file = os.path.join(os.getcwd(), f'website_security_analysis_error_{timestamp}.xlsx')
        generator = ExcelReportGenerator(fallback_data)
        generator.create_detailed_report(output_file)
        print(f"오류 보고서 생성: {output_file}")

    except Exception as fallback_error:
        print(f"오류 보고서 생성 실패: {str(fallback_error)}")
```

## 엑셀 보고서 구조

생성되는 엑셀 보고서는 다음 컬럼들을 포함한다:

| 컬럼명 | 설명 |
|--------|------|
| 메뉴 | 내비게이션 메뉴 이름 |
| URL | 해당 페이지 URL |
| 요소유형 | FORM, API, LINK 등 요소 분류 |
| 요소명 | 폼 액션, API 엔드포인트 등 |
| 파라미터 | 전송되는 파라미터 목록 및 타입 |
| HTTP메소드 | GET, POST, PUT, DELETE 등 |
| 취약점종류 | XSS, SQL_INJECTION, CSRF 등 |
| 위험도 | HIGH, MEDIUM, LOW |
| 상세설명 | 취약점 상세 설명 |
| 패턴 | 발견된 코드 패턴 |
| 인증필요 | 인증이 필요한지 여부 |
| 권장조치 | 개선을 위한 권장 사항 |

## 주요 분석 취약점 종류

1. **XSS (Cross-Site Scripting)**
   - DOM 기반 XSS
   - Reflected XSS
   - Stored XSS 패턴

2. **SQL Injection**
   - 동적 쿼리 생성 패턴
   - 파라미터 직접 사용 패턴

3. **CSRF (Cross-Site Request Forgery)**
   - CSRF 토큰 부재

4. **인증/권한**
   - 관리자 페이지 노출
   - 권한 체계 부재

5. **정보노출**
   - 상세 에러 메시지 노출
   - 디버그 정보 노출

6. **보안 헤더**
   - CSP, X-Frame-Options 등 부재

## 실행 완료 조건

다음 조건들이 모두 충족되어야 분석이 완료된다:
- 사이트의 모든 내비게이션 메뉴 탐색 완료
- 각 페이지의 모든 폼과 API 엔드포인트 분석 완료
- 모든 취약점 패턴 분석 완료
- 엑셀 보고서 생성 완료
- 분석 결과 요약 보고 제공

## CSV 파일 처리 사용법

한글로 된 CSV 파일을 처리할 때는 다음과 같이 `safe_read_csv` 함수를 사용한다:

```python
# CSV 파일 읽기 예시
try:
    # 현재 작업 디렉토리의 CSV 파일 읽기
    csv_file = "jupyterlab_security_analysis_raw.csv"
    df = safe_read_csv(csv_file)

    print(f"CSV 파일 로드 성공: {len(df)}개 행")
    print(f"컬럼: {list(df.columns)}")

    # 데이터 처리 후 엑셀 보고서 생성
    processed_data = process_analysis_results(df.to_dict('records'))
    generator = ExcelReportGenerator(processed_data)
    generator.create_detailed_report("security_report_from_csv.xlsx")

except FileNotFoundError:
    print(f"CSV 파일을 찾을 수 없습니다: {csv_file}")
except Exception as e:
    print(f"CSV 처리 중 오류 발생: {str(e)}")
```

## 중요 사항

- 이 스킬은 실제 공격을 수행하지 않고 코드 패턴 분석만 수행
- 모든 분석은 Chrome DevTools를 통한 안전한 방식으로 진행
- 결과는 취약점 가능성을 나타내며, 전문가의 추가 검토 필요
- 분석 대상 사이트의 약관과 robots.txt 준수 필수
- CSV 파일 처리 시 인코딩 문제를 자동으로 해결하며, 한글(UTF-8, CP949, EUC-KR) 인코딩을 지원