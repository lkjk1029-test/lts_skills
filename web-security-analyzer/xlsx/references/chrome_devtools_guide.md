# Chrome DevTools 웹 보안 분석 가이드

이 가이드는 Chrome DevTools MCP 서버를 사용하여 웹사이트 보안 분석을 수행하는 방법을 설명한다.

## Chrome DevTools MCP 기본 명령어

### 페이지 제어
```python
# 새 페이지 생성 및 URL 접속
await mcp__chrome_devtools__new_page("https://example.com")
await mcp__chrome_devtools__navigate_page("https://example.com")

# 페이지 이동 (뒤로/앞으로)
await mcp__chrome_devtools__navigate_page_history("back")
await mcp__chrome_devtools__navigate_page_history("forward")

# 페이지 닫기 (index 0부터 시작)
await mcp__chrome_devtools__close_page(0)
```

### 페이지 정보 분석
```python
# 페이지 스냅샷 생성 (DOM 구조 분석)
snapshot = await mcp__chrome_devtools__take_snapshot(verbose=True)

# 자바스크립트 실행 및 결과 얻기
result = await mcp__chrome_devtools__evaluate_script("""
() => {
    return {
        title: document.title,
        url: window.location.href,
        protocol: window.location.protocol,
        cookies: document.cookie
    }
}
""")
```

### 네트워크 분석
```python
# 네트워크 요청 목록 가져오기
network_requests = await mcp__chrome_devtools__list_network_requests(
    pageSize=100,
    resourceTypes=["document", "script", "xhr", "fetch", "image", "stylesheet"]
)

# 특정 네트워크 요청 상세 정보
request_detail = await mcp__chrome_devtools__get_network_request(reqid=1)
```

### 콘솔 메시지 분석
```python
# 콘솔 메시지 가져오기
console_messages = await mcp__chrome_devtools__list_console_messages(
    types=["error", "warn", "log", "info"],
    pageSize=50
)

# 특정 콘솔 메시지 상세 정보
message_detail = await mcp__chrome_devtools__get_console_message(msgid=1)
```

### 폼 및 입력 요소 조작
```python
# 폼 필드 채우기
await mcp__chrome_devtools__fill_form([
    {"uid": "username_field", "value": "testuser"},
    {"uid": "password_field", "value": "testpass"}
])

# 특정 요소 클릭
await mcp__chrome_devtools__click(uid="submit_button")

# 요소 위로 마우스 호버
await mcp__chrome_devtools__hover(uid="menu_item")
```

### 파일 업로드
```python
# 파일 업로드
await mcp__chrome_devtools__upload_file(
    uid="file_input",
    filePath="C:\\path\\to\\testfile.txt"
)
```

## 웹 보안 분석 자동화 스크립트

### 1. 기본 사이트 정보 수집
```python
async def collect_basic_info():
    """웹사이트 기본 정보 수집"""

    # 페이지 기본 정보
    basic_info = await mcp__chrome_devtools__evaluate_script("""
    () => {
        return {
            title: document.title,
            url: window.location.href,
            domain: window.location.hostname,
            protocol: window.location.protocol,
            port: window.location.port,
            path: window.location.pathname,
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            cookies: document.cookie,
            localStorage: Object.keys(localStorage),
            sessionStorage: Object.keys(sessionStorage),
            referrer: document.referrer,
            lastModified: document.lastModified
        }
    }
    """)

    return basic_info
```

### 2. HTTPS 및 보안 설정 확인
```python
async def check_https_security():
    """HTTPS 및 보안 설정 확인"""

    security_info = await mcp__chrome_devtools__evaluate_script("""
    () => {
        const isHTTPS = window.location.protocol === 'https:';
        const mixedContent = {
            httpImages: document.querySelectorAll('img[src^="http:"]').length,
            httpScripts: document.querySelectorAll('script[src^="http:"]').length,
            httpStyles: document.querySelectorAll('link[href^="http:"]').length,
            httpIframes: document.querySelectorAll('iframe[src^="http:"]').length
        };

        // CSP 헤더 확인 (meta tag)
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');

        // 보안 관련 헤더 확인 (JavaScript로는 직접 확인 불가, 네트워크 탭 필요)

        return {
            isHTTPS,
            mixedContent,
            cspMeta: cspMeta ? cspMeta.content : null,
            totalMixedContent: Object.values(mixedContent).reduce((a, b) => a + b, 0)
        };
    }
    """)

    return security_info
```

### 3. 폼 및 입력 필드 분석
```python
async def analyze_forms():
    """폼 및 입력 필드 분석"""

    forms_data = await mcp__chrome_devtools__evaluate_script("""
    () => {
        const forms = [];
        document.querySelectorAll('form').forEach((form, index) => {
            const formData = {
                index,
                action: form.action,
                method: form.method.toUpperCase() || 'GET',
                id: form.id,
                className: form.className,
                name: form.name,
                enctype: form.enctype,
                autocomplete: form.getAttribute('autocomplete'),
                novalidate: form.hasAttribute('novalidate'),
                fields: []
            };

            // 입력 필드 분석
            form.querySelectorAll('input, select, textarea').forEach(field => {
                const fieldData = {
                    type: field.type || field.tagName.toLowerCase(),
                    name: field.name || field.id || '',
                    id: field.id || '',
                    className: field.className || '',
                    required: field.required || field.hasAttribute('required'),
                    readonly: field.readOnly || field.hasAttribute('readonly'),
                    disabled: field.disabled || field.hasAttribute('disabled'),
                    placeholder: field.placeholder || '',
                    value: field.value || '',
                    maxLength: field.maxLength || -1,
                    pattern: field.pattern || '',
                    autocomplete: field.getAttribute('autocomplete') || '',
                    // 보안 관련 속성
                    isPassword: field.type === 'password',
                    isEmail: field.type === 'email',
                    isTel: field.type === 'tel',
                    isNumber: field.type === 'number',
                    isDate: field.type === 'date',
                    // 파일 업로드 필드
                    isFile: field.type === 'file',
                    accept: field.accept || '',
                    // 숨겨진 필드
                    isHidden: field.type === 'hidden'
                };
                formData.fields.push(fieldData);
            });

            forms.push(formData);
        });

        return forms;
    }
    """)

    return forms_data
```

### 4. 링크 및 내비게이션 구조 분석
```python
async def analyze_navigation():
    """링크 및 내비게이션 구조 분석"""

    nav_info = await mcp__chrome_devtools__evaluate_script("""
    () => {
        // 모든 링크 분석
        const allLinks = [];
        document.querySelectorAll('a[href]').forEach(link => {
            const href = link.href;
            const isInternal = href.includes(window.location.hostname);
            const isAnchor = href.includes('#');
            const isJavaScript = href.startsWith('javascript:');

            allLinks.push({
                text: link.textContent.trim(),
                href: href,
                isInternal,
                isAnchor,
                isJavaScript,
                id: link.id || '',
                className: link.className || '',
                target: link.target || '',
                rel: link.rel || '',
                download: link.download || ''
            });
        });

        // 내비게이션 메뉴 분석
        const navMenus = [];
        document.querySelectorAll('nav, .nav, .navigation, .menu').forEach(nav => {
            const menuData = {
                id: nav.id || '',
                className: nav.className || '',
                tagName: nav.tagName.toLowerCase(),
                links: []
            };

            nav.querySelectorAll('a[href]').forEach(link => {
                if (!link.href.startsWith('javascript:') && !link.href.includes('#')) {
                    menuData.links.push({
                        text: link.textContent.trim(),
                        href: link.href,
                        isInternal: link.href.includes(window.location.hostname)
                    });
                }
            });

            navMenus.push(menuData);
        });

        return {
            totalLinks: allLinks.length,
            internalLinks: allLinks.filter(l => l.isInternal && !l.isAnchor).length,
            externalLinks: allLinks.filter(l => !l.isInternal).length,
            anchorLinks: allLinks.filter(l => l.isAnchor).length,
            javascriptLinks: allLinks.filter(l => l.isJavaScript).length,
            navMenus,
            allLinks: allLinks.filter(l => !l.isAnchor && !l.isJavaScript)
        };
    }
    """)

    return nav_info
```

### 5. 쿠키 및 스토리지 분석
```python
async def analyze_storage():
    """쿠키 및 스토리지 분석"""

    storage_info = await mcp__chrome_devtools__evaluate_script("""
    () => {
        // 쿠키 분석
        const cookies = document.cookie.split(';').map(cookie => {
            const [name, value] = cookie.trim().split('=');
            return {
                name: name || '',
                value: value || '',
                isSecure: document.cookie.includes(`${name}=`) && window.location.protocol === 'https:',
                isHttpOnly: false // JavaScript로는 HttpOnly 확인 불가
            };
        }).filter(cookie => cookie.name);

        // localStorage 분석
        const localStorageData = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            localStorageData[key] = localStorage.getItem(key);
        }

        // sessionStorage 분석
        const sessionStorageData = {};
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            sessionStorageData[key] = sessionStorage.getItem(key);
        }

        return {
            cookies: {
                count: cookies.length,
                items: cookies
            },
            localStorage: {
                count: Object.keys(localStorageData).length,
                items: localStorageData
            },
            sessionStorage: {
                count: Object.keys(sessionStorageData).length,
                items: sessionStorageData
            }
        };
    }
    """)

    return storage_info
```

### 6. 콘솔 오류 및 경고 분석
```python
async def analyze_console_errors():
    """콘솔 오류 및 경고 분석"""

    # 에러 메시지만 필터링
    error_messages = await mcp__chrome_devtools__list_console_messages(
        types=["error"],
        pageSize=100
    )

    # 경고 메시지만 필터링
    warning_messages = await mcp__chrome_devtools__list_console_messages(
        types=["warn"],
        pageSize=100
    )

    return {
        errors: error_messages,
        warnings: warning_messages,
        errorCount: len(error_messages),
        warningCount: len(warning_messages)
    }
```

### 7. 네트워크 요청 분석
```python
async def analyze_network_requests():
    """네�트워크 요청 분석"""

    # 모든 네트워크 요청 가져오기
    network_requests = await mcp__chrome_devtools__list_network_requests(
        pageSize=200,
        resourceTypes=["document", "script", "xhr", "fetch", "image", "stylesheet", "font", "media"]
    )

    # 요청 유형별 분류
    analysis = {
        total: len(network_requests),
        byType: {},
        httpsRequests: 0,
        httpRequests: 0,
        externalRequests: 0,
        internalRequests: 0,
        apiEndpoints: [],
        potentialVulnerabilities: []
    }

    for request in network_requests:
        # 요청 유형별 분류
        reqType = request.get('type', 'unknown')
        analysis.byType[reqType] = analysis.byType.get(reqType, 0) + 1

        # HTTP/HTTPS 분류
        url = request.get('url', '')
        if url.startswith('https://'):
            analysis.httpsRequests += 1
        elif url.startswith('http://'):
            analysis.httpRequests += 1

        # 내부/외부 요청 분류
        if 'localhost' in url or '127.0.0.1' in url:
            analysis.internalRequests += 1
        else:
            analysis.externalRequests += 1

        # API 엔드포인트 식별
        if reqType in ['xhr', 'fetch'] and '/api/' in url:
            analysis.apiEndpoints.append({
                url: url,
                method: request.get('method', 'GET'),
                type: reqType
            })

        # 잠재적 취약점 확인
        if 'password' in url.lower() or 'token' in url.lower():
            if request.get('method') === 'GET':
                analysis.potentialVulnerabilities.append({
                    type: 'Sensitive Data in URL',
                    url: url,
                    method: request.get('method', 'GET')
                })

    return analysis
```

### 8. 로그인 프로세스 자동화
```python
async def perform_login(username, password, login_url=None):
    """로그인 프로세스 자동화"""

    if login_url:
        await mcp__chrome_devtools__navigate_page(login_url)

    # 스냅샷으로 로그인 폼 찾기
    snapshot = await mcp__chrome_devtools__take_snapshot(verbose=True)

    # 로그인 폼 필드 찾기 (실제 구현에서는 스냅샷 분석 필요)
    login_fields = await mcp__chrome_devtools__evaluate_script("""
    () => {
        // 일반적인 로그인 필드 선택자
        const selectors = {
            username: [
                'input[type="text"][name*="user"]',
                'input[type="text"][name*="email"]',
                'input[type="email"]',
                'input[name*="login"]',
                'input[id*="user"]',
                'input[id*="email"]',
                'input[placeholder*="user"]',
                'input[placeholder*="email"]'
            ],
            password: [
                'input[type="password"]',
                'input[name*="pass"]',
                'input[id*="pass"]'
            ],
            submit: [
                'input[type="submit"]',
                'button[type="submit"]',
                'button[name*="login"]',
                'button[name*="submit"]',
                'button[id*="login"]'
            ]
        };

        const findField = (selectorList) => {
            for (const selector of selectorList) {
                const element = document.querySelector(selector);
                if (element) return element;
            }
            return null;
        };

        const usernameField = findField(selectors.username);
        const passwordField = findField(selectors.password);
        const submitButton = findField(selectors.submit);

        return {
            usernameFound: !!usernameField,
            passwordFound: !!passwordField,
            submitFound: !!submitButton,
            form: usernameField ? usernameField.closest('form') : null
        };
    }
    """)

    # 로그인 필드가 발견되면 로그인 시도
    if login_fields['usernameFound'] and login_fields['passwordFound']:
        await mcp__chrome_devtools__fill_form([
            {"uid": "username_field", "value": username},
            {"uid": "password_field", "value": password}
        ])

        if login_fields['submitFound']:
            await mcp__chrome_devtools__click(uid="submit_button")
            return {"success": True, "message": "로그인 시도 완료"}
        else:
            return {"success": False, "message": "로그인 버튼을 찾을 수 없음"}
    else:
        return {"success": False, "message": "로그인 필드를 찾을 수 없음"}
```

## 통합 분석 스크립트

### 전체 웹사이트 보안 분석
```python
async def comprehensive_security_analysis(target_url, username=None, password=None):
    """종합적인 웹사이트 보안 분석 수행"""

    analysis_results = {
        target_url: target_url,
        timestamp: datetime.now().isoformat(),
        analysis: {}
    }

    try:
        # 1. 페이지 접속
        await mcp__chrome_devtools__new_page(target_url)

        # 2. 로그인 처리 (필요시)
        if username and password:
            login_result = await perform_login(username, password)
            analysis_results['login'] = login_result

        # 3. 기본 정보 수집
        analysis_results['analysis']['basic_info'] = await collect_basic_info()

        # 4. HTTPS 보안 확인
        analysis_results['analysis']['security'] = await check_https_security()

        # 5. 폼 분석
        analysis_results['analysis']['forms'] = await analyze_forms()

        # 6. 내비게이션 분석
        analysis_results['analysis']['navigation'] = await analyze_navigation()

        # 7. 스토리지 분석
        analysis_results['analysis']['storage'] = await analyze_storage()

        # 8. 콘솔 오류 분석
        analysis_results['analysis']['console'] = await analyze_console_errors()

        # 9. 네트워크 분석
        analysis_results['analysis']['network'] = await analyze_network_requests()

        # 10. 취약점 요약
        analysis_results['vulnerabilities'] = summarize_vulnerabilities(analysis_results['analysis'])

        return analysis_results

    except Exception as e:
        analysis_results['error'] = str(e)
        return analysis_results

def summarize_vulnerabilities(analysis_data):
    """분석 데이터에서 취약점 요약"""

    vulnerabilities = {
        high: [],
        medium: [],
        low: []
    }

    # HTTPS 관련 취약점
    if not analysis_data['security']['isHTTPS']:
        vulnerabilities['high'].append("HTTP 프로토콜 사용 - HTTPS로 전환 필요")

    if analysis_data['security']['totalMixedContent'] > 0:
        vulnerabilities['medium'].append(f"Mixed Content 발견: {analysis_data['security']['totalMixedContent']}개")

    # 폼 관련 취약점
    for form in analysis_data['forms']:
        if form['method'] === 'GET' and any(field['isPassword'] for field in form['fields']):
            vulnerabilities['high'].append("비밀번호 전송에 GET 방식 사용")

        for field in form['fields']:
            if field['isPassword'] and not field['autocomplete']:
                vulnerabilities['low'].append("비밀번호 필드에 autocomplete 비활성화")

    # 콘솔 오류
    if analysis_data['console']['errorCount'] > 0:
        vulnerabilities['medium'].append(f"콘솔 오류 {analysis_data['console']['errorCount']}개 발견")

    # 민감정보 URL 노출
    if analysis_data['network']['potentialVulnerabilities']:
        for vuln in analysis_data['network']['potentialVulnerabilities']:
            vulnerabilities['high'].append(f"민감정보 URL 노출: {vuln['url']}")

    return vulnerabilities
```

## 성능 최적화 팁

### 1. 병렬 분석
```python
import asyncio

async def parallel_analysis(target_url):
    """여러 분석 작업을 병렬로 실행"""

    await mcp__chrome_devtools__new_page(target_url)

    # 독립적인 분석 작업들을 병렬로 실행
    tasks = [
        collect_basic_info(),
        check_https_security(),
        analyze_forms(),
        analyze_navigation(),
        analyze_storage()
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    return {
        'basic_info': results[0],
        'security': results[1],
        'forms': results[2],
        'navigation': results[3],
        'storage': results[4]
    }
```

### 2. 대기 시간 최적화
```python
# 페이지 로딩 대기
await mcp__chrome_devtools__wait_for("DOMContentLoaded", timeout=10000)

# 특정 요소 대기
await mcp__chrome_devtools__wait_for("document.querySelector('.content')", timeout=5000)

# 네트워크 활동 대기
await asyncio.sleep(2)  # 네트워크 요청이 완료될 때까지 잠시 대기
```

### 3. 에러 처리
```python
async def safe_analysis(target_url):
    """안전한 분석 실행 - 에러 처리 포함"""

    try:
        results = await comprehensive_security_analysis(target_url)
        return results
    except Exception as e:
        return {
            'target_url': target_url,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }
```

이 가이드를 사용하면 Chrome DevTools MCP 서버를 활용하여 체계적인 웹사이트 보안 분석을 자동화할 수 있다.