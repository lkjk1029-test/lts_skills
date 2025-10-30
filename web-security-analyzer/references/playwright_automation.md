# Playwright 웹 보안 분석 자동화 가이드

이 가이드는 Playwright MCP 서버를 사용하여 웹사이트 보안 분석을 자동화하는 방법을 설명한다.

## Playwright MCP 기본 명령어

### 브라우저 제어
```python
# 브라우저 시작 및 페이지 네비게이션
await mcp__playwright__browser_navigate("https://example.com")

# 브라우저 창 크기 조절
await mcp__playwright__browser_resize(width=1920, height=1080)

# 브라우저 닫기
await mcp__playwright__browser_close()
```

### 페이지 분석
```python
# 페이지 스냅샷 생성 (DOM 구조 분석)
snapshot = await mcp__playwright__browser_snapshot()

# 자바스크립트 실행 및 결과 얻기
result = await mcp__playwright__browser_evaluate(
    function="() => { return document.title; }"
)
```

### 요소 상호작용
```python
# 클릭 이벤트
await mcp__playwright__browser_click(
    element="로그인 버튼",
    ref="button[type='submit']"
)

# 텍스트 입력
await mcp__playwright__browser_type(
    element="사용자 이름 입력 필드",
    ref="input[name='username']",
    text="testuser"
)

# 폼 필드 채우기 (여러 필드)
await mcp__playwright__browser_fill_form(fields=[
    {
        "name": "사용자 이름",
        "type": "textbox",
        "ref": "input[name='username']",
        "value": "testuser"
    },
    {
        "name": "비밀번호",
        "type": "textbox",
        "ref": "input[name='password']",
        "value": "testpass"
    }
])

# 요소 위로 마우스 호버
await mcp__playwright__browser_hover(
    element="메뉴 아이템",
    ref="nav ul li:first-child"
)
```

### 고급 상호작용
```python
# 드래그 앤 드롭
await mcp__playwright__browser_drag(
    startElement="드래그할 요소",
    startRef=".draggable-item",
    endElement="드롭 영역",
    endRef=".drop-zone"
)

# 키보드 입력
await mcp__playwright__browser_press_key(key="Enter")

# 파일 업로드
await mcp__playwright__browser_file_upload(paths=["C:\\path\\to\\testfile.txt"])

# 선택 박스에서 옵션 선택
await mcp__playwright__browser_select_option(
    element="국가 선택",
    ref="select[name='country']",
    values=["KR", "US"]
)
```

### 대기 및 타이밍
```python
# 특정 시간 대기
await mcp__playwright__browser_wait_for(time=3, text="", textGone="")

# 텍스트가 나타날 때까지 대기
await mcp__playwright__browser_wait_for(time=10, text="로그인 성공")

# 텍스트가 사라질 때까지 대기
await mcp__playwright__browser_wait_for(time=5, text="", textGone="로딩 중...")
```

### 스크린샷 및 모니터링
```python
# 전체 페이지 스크린샷
await mcp__playwright__browser_take_screenshot(
    type="png",
    filename="full_page.png",
    element="전체 페이지",
    ref="",
    fullPage=True
)

# 특정 요소 스크린샷
await mcp__playwright__browser_take_screenshot(
    type="png",
    filename="login_form.png",
    element="로그인 폼",
    ref="form[id='login']",
    fullPage=False
)

# 콘솔 에러 메시지만 확인
console_errors = await mcp__playwright__browser_console_messages(onlyErrors=True)

# 모든 콘솔 메시지 확인
all_console_messages = await mcp__playwright__browser_console_messages(onlyErrors=False)

# 네트워크 요청 확인
network_requests = await mcp__playwright__browser_network_requests()
```

## 웹 보안 분석 자동화 스크립트

### 1. 기본 사이트 정보 수집
```python
async def collect_basic_site_info():
    """웹사이트 기본 정보 수집"""

    basic_info = await mcp__playwright__browser_evaluate("""
    () => {
        return {
            title: document.title,
            url: window.location.href,
            domain: window.location.hostname,
            protocol: window.location.protocol,
            port: window.location.port,
            path: window.location.pathname,
            search: window.location.search,
            hash: window.location.hash,
            userAgent: navigator.userAgent,
            language: navigator.language,
            languages: navigator.languages,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            onLine: navigator.onLine,
            referrer: document.referrer,
            lastModified: document.lastModified,
            readyState: document.readyState,
            characterSet: document.characterSet,
            contentType: document.contentType,
            doctype: document.doctype ? document.doctype.name : null,
            // Meta 정보
            metaTags: Array.from(document.querySelectorAll('meta')).map(meta => ({
                name: meta.name || meta.getAttribute('property') || '',
                content: meta.content || '',
                charset: meta.charset || '',
                httpEquiv: meta.httpEquiv || ''
            })),
            // Viewport 설정
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight,
                devicePixelRatio: window.devicePixelRatio
            }
        };
    }
    """)

    return basic_info
```

### 2. 보안 헤더 및 HTTPS 분석
```python
async def analyze_security_headers():
    """보안 헤더 및 HTTPS 설정 분석"""

    security_analysis = await mcp__playwright__browser_evaluate("""
    () => {
        const isHTTPS = window.location.protocol === 'https:';
        const securityInfo = {
            isHTTPS,
            mixedContent: {
                httpResources: document.querySelectorAll('[src^="http:"], [href^="http:"]').length,
                httpImages: document.querySelectorAll('img[src^="http:"]').length,
                httpScripts: document.querySelectorAll('script[src^="http:"]').length,
                httpStyles: document.querySelectorAll('link[href^="http:"]').length,
                httpIframes: document.querySelectorAll('iframe[src^="http:"]').length
            },
            cspMeta: null,
            securityMetaTags: []
        };

        // CSP Meta 태그 확인
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        if (cspMeta) {
            securityInfo.cspMeta = cspMeta.content;
        }

        // 기타 보안 관련 Meta 태그
        const securityMetas = document.querySelectorAll('meta[http-equiv]');
        securityMetas.forEach(meta => {
            if (meta.httpEquiv.toLowerCase().includes('security') ||
                meta.httpEquiv.toLowerCase().includes('policy')) {
                securityInfo.securityMetaTags.push({
                    httpEquiv: meta.httpEquiv,
                    content: meta.content
                });
            }
        });

        // 외부 리소스 분석
        const externalResources = [];
        document.querySelectorAll('link[href], script[src], img[src]').forEach(resource => {
            const url = resource.src || resource.href;
            if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                const isExternal = !url.includes(window.location.hostname);
                const isHTTP = url.startsWith('http://');

                if (isExternal || isHTTP) {
                    externalResources.push({
                        tagName: resource.tagName.toLowerCase(),
                        url: url,
                        isExternal,
                        isHTTP,
                        integrity: resource.getAttribute('integrity') || '',
                        crossorigin: resource.getAttribute('crossorigin') || ''
                    });
                }
            }
        });

        securityInfo.externalResources = externalResources;
        securityInfo.totalExternalResources = externalResources.length;
        securityInfo.totalHTTPResources = externalResources.filter(r => r.isHTTP).length;

        return securityInfo;
    }
    """)

    return security_analysis
```

### 3. 폼 및 입력 필드 심층 분석
```python
async def analyze_forms_detailed():
    """폼 및 입력 필드 심층 분석"""

    forms_analysis = await mcp__playwright__browser_evaluate("""
    () => {
        const forms = [];
        document.querySelectorAll('form').forEach((form, index) => {
            const formData = {
                index,
                action: form.action || '',
                method: (form.method || 'GET').toUpperCase(),
                id: form.id || '',
                className: form.className || '',
                name: form.name || '',
                enctype: form.enctype || 'application/x-www-form-urlencoded',
                autocomplete: form.getAttribute('autocomplete') || '',
                novalidate: form.hasAttribute('novalidate'),
                target: form.target || '_self',
                fields: [],
                potentialVulnerabilities: []
            };

            // CSRF 토큰 확인
            const csrfToken = form.querySelector('input[name*="csrf"], input[name*="token"]');
            formData.csrfToken = csrfToken ? csrfToken.name : null;

            // 입력 필드 분석
            form.querySelectorAll('input, select, textarea, button').forEach(field => {
                const fieldData = {
                    tagName: field.tagName.toLowerCase(),
                    type: field.type || field.tagName.toLowerCase(),
                    name: field.name || '',
                    id: field.id || '',
                    className: field.className || '',
                    placeholder: field.placeholder || '',
                    value: field.value || '',
                    required: field.required || field.hasAttribute('required'),
                    readonly: field.readOnly || field.hasAttribute('readonly'),
                    disabled: field.disabled || field.hasAttribute('disabled'),
                    autocomplete: field.getAttribute('autocomplete') || '',
                    maxlength: field.maxLength || -1,
                    minlength: field.minLength || -1,
                    min: field.min || '',
                    max: field.max || '',
                    step: field.step || '',
                    pattern: field.pattern || '',
                    // 보안 관련 속성
                    isPassword: field.type === 'password',
                    isEmail: field.type === 'email',
                    isTel: field.type === 'tel',
                    isNumber: field.type === 'number',
                    isDate: field.type === 'date',
                    isFile: field.type === 'file',
                    isHidden: field.type === 'hidden',
                    isButton: field.type === 'button' || field.type === 'submit',
                    // 파일 업로드 관련
                    accept: field.accept || '',
                    multiple: field.multiple || false,
                    // 버튼 관련
                    buttonType: field.type || 'button'
                };

                // 잠재적 취약점 확인
                if (fieldData.isPassword && fieldData.autocomplete === 'off') {
                    formData.potentialVulnerabilities.push({
                        type: 'Password autocomplete disabled',
                        field: fieldData.name || fieldData.id,
                        severity: 'Low'
                    });
                }

                if (fieldData.isPassword && formData.method === 'GET') {
                    formData.potentialVulnerabilities.push({
                        type: 'Password in GET request',
                        field: fieldData.name || fieldData.id,
                        severity: 'High'
                    });
                }

                if (fieldData.isHidden && fieldData.name.toLowerCase().includes('price') ||
                    fieldData.name.toLowerCase().includes('amount')) {
                    formData.potentialVulnerabilities.push({
                        type: 'Hidden sensitive data',
                        field: fieldData.name || fieldData.id,
                        severity: 'Medium'
                    });
                }

                formData.fields.push(fieldData);
            });

            // 폼 액션 URL 분석
            if (formData.action && formData.action.startsWith('http://')) {
                formData.potentialVulnerabilities.push({
                    type: 'Insecure form action (HTTP)',
                    action: formData.action,
                    severity: 'High'
                });
            }

            forms.push(formData);
        });

        return forms;
    }
    """)

    return forms_analysis
```

### 4. 내비게이션 및 링크 구조 분석
```python
async def analyze_navigation_structure():
    """내비게이션 및 링크 구조 분석"""

    navigation_analysis = await mcp__playwright__browser_evaluate("""
    () => {
        // 모든 링크 분석
        const allLinks = Array.from(document.querySelectorAll('a[href]')).map(link => {
            const href = link.href;
            const isInternal = href.includes(window.location.hostname);
            const isAnchor = href.includes('#') && new URL(href).pathname === window.location.pathname;
            const isJavaScript = href.startsWith('javascript:');
            const isMailto = href.startsWith('mailto:');
            const isTel = href.startsWith('tel:');
            const isExternal = !isInternal && !isJavaScript && !isMailto && !isTel;

            return {
                text: link.textContent.trim(),
                href: href,
                isInternal,
                isExternal,
                isAnchor,
                isJavaScript,
                isMailto,
                isTel,
                id: link.id || '',
                className: link.className || '',
                target: link.target || '',
                rel: link.rel || '',
                download: link.download || '',
                title: link.title || '',
                // 접근성 관련
                ariaLabel: link.getAttribute('aria-label') || '',
                role: link.getAttribute('role') || ''
            };
        });

        // 내비게이션 메뉴 구조 분석
        const navStructures = [];
        const navSelectors = [
            'nav', 'header nav', '.navigation', '.nav', '.menu',
            '.main-menu', '.top-menu', '.sidebar', '.breadcrumb'
        ];

        navSelectors.forEach(selector => {
            document.querySelectorAll(selector).forEach((nav, index) => {
                const navData = {
                    selector,
                    index,
                    id: nav.id || '',
                    className: nav.className || '',
                    tagName: nav.tagName.toLowerCase(),
                    links: [],
                    hierarchy: []
                };

                // 링크 계층 구조 분석
                const links = nav.querySelectorAll('a[href]');
                links.forEach(link => {
                    if (!link.href.startsWith('javascript:') && !link.href.includes('#')) {
                        const linkData = {
                            text: link.textContent.trim(),
                            href: link.href,
                            isInternal: link.href.includes(window.location.hostname),
                            depth: 0, // 부모 요소의 깊이 계산 필요
                            parentId: '',
                            // 부모 요소 정보
                            parentTag: link.parentElement ? link.parentElement.tagName.toLowerCase() : '',
                            parentClass: link.parentElement ? link.parentElement.className : ''
                        };

                        // 깊이 계산
                        let parent = link.parentElement;
                        let depth = 0;
                        while (parent && parent !== nav) {
                            depth++;
                            parent = parent.parentElement;
                        }
                        linkData.depth = depth;

                        navData.links.push(linkData);
                    }
                });

                navStructures.push(navData);
            });
        });

        // 사이트맵 분석 (footer, breadcrumbs 등)
        const sitemapElements = document.querySelectorAll('.sitemap, .footer nav, .breadcrumb, .breadcrumbs');
        const sitemapLinks = [];

        sitemapElements.forEach(element => {
            element.querySelectorAll('a[href]').forEach(link => {
                if (!link.href.startsWith('javascript:') && !link.href.includes('#')) {
                    sitemapLinks.push({
                        text: link.textContent.trim(),
                        href: link.href,
                        context: element.className || element.tagName.toLowerCase()
                    });
                }
            });
        });

        return {
            totalLinks: allLinks.length,
            internalLinks: allLinks.filter(l => l.isInternal && !l.isAnchor).length,
            externalLinks: allLinks.filter(l => l.isExternal).length,
            anchorLinks: allLinks.filter(l => l.isAnchor).length,
            javascriptLinks: allLinks.filter(l => l.isJavaScript).length,
            mailtoLinks: allLinks.filter(l => l.isMailto).length,
            telLinks: allLinks.filter(l => l.isTel).length,
            navStructures,
            sitemapLinks,
            allLinks: allLinks.filter(l => !l.isAnchor && !l.isJavaScript && !l.isMailto && !l.isTel)
        };
    }
    """)

    return navigation_analysis
```

### 5. 스토리지 및 쿠키 분석
```python
async def analyze_storage_and_cookies():
    """스토리지 및 쿠키 분석"""

    storage_analysis = await mcp__playwright__browser_evaluate("""
    () => {
        // 쿠키 분석
        const cookies = document.cookie.split(';').map(cookie => {
            const [name, ...valueParts] = cookie.trim().split('=');
            const value = valueParts.join('=');
            return {
                name: name || '',
                value: value || '',
                domain: window.location.hostname,
                path: window.location.pathname,
                isSecure: window.location.protocol === 'https:',
                isHttpOnly: false, // JavaScript로 확인 불가
                isSession: true, // 만료 시간 확인 불가
                size: (name + value).length
            };
        }).filter(cookie => cookie.name);

        // localStorage 분석
        const localStorageData = {};
        let localStorageSize = 0;
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            localStorageData[key] = {
                value: value,
                size: (key + value).length
            };
            localStorageSize += (key + value).length;
        }

        // sessionStorage 분석
        const sessionStorageData = {};
        let sessionStorageSize = 0;
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            const value = sessionStorage.getItem(key);
            sessionStorageData[key] = {
                value: value,
                size: (key + value).length
            };
            sessionStorageSize += (key + value).length;
        }

        // IndexedDB 확인 (간단한 확인만)
        const indexedDBExists = 'indexedDB' in window;
        const indexedDBDatabases = indexedDBExists ? [] : [];

        // 잠재적 민감정보 확인
        const sensitivePatterns = [
            /password/i, /token/i, /api[_-]?key/i, /secret/i,
            /session/i, /auth/i, /user/i, /email/i, /phone/i
        ];

        const checkSensitiveData = (data, container) => {
            const sensitive = [];
            for (const [key, info] of Object.entries(data)) {
                if (typeof info === 'object' && info.value) {
                    for (const pattern of sensitivePatterns) {
                        if (pattern.test(key) || pattern.test(info.value)) {
                            sensitive.push({
                                container,
                                key,
                                pattern: pattern.source,
                                size: info.size
                            });
                            break;
                        }
                    }
                }
            }
            return sensitive;
        };

        const sensitiveData = [
            ...checkSensitiveData(localStorageData, 'localStorage'),
            ...checkSensitiveData(sessionStorageData, 'sessionStorage')
        ];

        return {
            cookies: {
                count: cookies.length,
                items: cookies,
                totalSize: cookies.reduce((sum, cookie) => sum + cookie.size, 0)
            },
            localStorage: {
                count: Object.keys(localStorageData).length,
                items: localStorageData,
                totalSize: localStorageSize
            },
            sessionStorage: {
                count: Object.keys(sessionStorageData).length,
                items: sessionStorageData,
                totalSize: sessionStorageSize
            },
            indexedDB: {
                exists: indexedDBExists,
                databases: indexedDBDatabases
            },
            sensitiveData,
            totalStorageSize: localStorageSize + sessionStorageSize
        };
    }
    """)

    return storage_analysis
```

### 6. JavaScript 및 동적 콘텐츠 분석
```python
async def analyze_javascript_and_dynamic_content():
    """JavaScript 및 동적 콘텐츠 분석"""

    js_analysis = await mcp__playwright__browser_evaluate("""
    () => {
        // 외부 JavaScript 라이브러리 확인
        const scripts = Array.from(document.querySelectorAll('script[src]')).map(script => ({
            src: script.src,
            isExternal: !script.src.includes(window.location.hostname),
            integrity: script.integrity || '',
            crossorigin: script.crossorigin || '',
            async: script.async || script.hasAttribute('async'),
            defer: script.defer || script.hasAttribute('defer'),
            type: script.type || 'text/javascript'
        }));

        // 인라인 스크립트 확인
        const inlineScripts = Array.from(document.querySelectorAll('script:not([src])')).map(script => ({
            content: script.textContent.substring(0, 200), // 처음 200자만
            hasSensitiveData: /password|token|api[_-]?key|secret/i.test(script.textContent)
        }));

        // jQuery 및 다른 라이브러리 확인
        const libraries = {};

        if (typeof jQuery !== 'undefined') {
            libraries.jquery = {
                version: jQuery.fn.jquery,
                exists: true
            };
        }

        if (typeof $ !== 'undefined' && $ !== jQuery) {
            libraries.jqueryAlias = {
                exists: true,
                version: $.fn ? $.fn.jquery : 'unknown'
            };
        }

        // Angular 확인
        if (typeof angular !== 'undefined') {
            libraries.angular = {
                version: angular.version.full,
                exists: true
            };
        }

        // React 확인
        if (typeof React !== 'undefined') {
            libraries.react = {
                version: React.version || 'unknown',
                exists: true
            };
        }

        // Vue 확인
        if (typeof Vue !== 'undefined') {
            libraries.vue = {
                version: Vue.version || 'unknown',
                exists: true
            };
        }

        // 이벤트 리스너 분석
        const elementCounts = {
            total: document.querySelectorAll('*').length,
            withOnclick: document.querySelectorAll('[onclick]').length,
            withOnsubmit: document.querySelectorAll('[onsubmit]').length,
            withOnload: document.querySelectorAll('[onload]').length,
            withOnerror: document.querySelectorAll('[onerror]').length
        };

        // AJAX 가능성 확인
        const ajaxLibraries = {
            xmlhttprequest: typeof XMLHttpRequest !== 'undefined',
            fetch: typeof fetch !== 'undefined',
            jqueryAjax: typeof jQuery !== 'undefined' && typeof jQuery.ajax === 'function'
        };

        // 콘솔 로그 확인 (디버깅 정보 노출)
        const consoleLogFound = (
            document.body.textContent.includes('console.log') ||
            document.body.textContent.includes('console.error') ||
            document.body.textContent.includes('console.warn')
        );

        return {
            scripts: {
                external: scripts.filter(s => s.isExternal),
                internal: scripts.filter(s => !s.isExternal),
                total: scripts.length
            },
            inlineScripts: {
                count: inlineScripts.length,
                withSensitiveData: inlineScripts.filter(s => s.hasSensitiveData).length
            },
            libraries,
            elementCounts,
            ajaxLibraries,
            consoleLogFound,
            // SPA (Single Page Application) 가능성
            spaIndicators: {
                hashRouting: window.location.hash.length > 0,
                pushStateSupported: typeof history !== 'undefined' && typeof history.pushState === 'function',
                dynamicContent: document.querySelectorAll('[data-ng-app], [ng-app], #app, .app').length > 0
            }
        };
    }
    """)

    return js_analysis
```

### 7. 로그인 자동화 및 인증 분석
```python
async def automated_login_analysis(login_url, username, password):
    """로그인 프로세스 자동화 및 인증 분석"""

    try:
        # 로그인 페이지로 이동
        await mcp__playwright__browser_navigate(login_url)

        # 로그인 폰 찾기 및 분석
        login_form_info = await mcp__playwright__browser_evaluate("""
        () => {
            const formSelectors = [
                'form', 'form[id*="login"]', 'form[class*="login"]',
                'form[action*="login"]', 'form[name*="login"]'
            ];

            let loginForm = null;
            for (const selector of formSelectors) {
                const form = document.querySelector(selector);
                if (form) {
                    loginForm = form;
                    break;
                }
            }

            if (!loginForm) {
                return { found: false, message: 'Login form not found' };
            }

            const usernameSelectors = [
                'input[type="text"][name*="user"]',
                'input[type="text"][name*="email"]',
                'input[type="email"]',
                'input[name*="login"]',
                'input[id*="user"]',
                'input[id*="email"]',
                'input[placeholder*="user"]',
                'input[placeholder*="email"]'
            ];

            const passwordSelectors = [
                'input[type="password"]',
                'input[name*="pass"]',
                'input[id*="pass"]'
            ];

            const submitSelectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'button[name*="login"]',
                'button[name*="submit"]',
                'button[id*="login"]',
                'button:contains("로그인")',
                'button:contains("Login")',
                'button:contains("Sign In")'
            ];

            const findField = (selectors) => {
                for (const selector of selectors) {
                    const element = document.querySelector(selector);
                    if (element) return element;
                }
                return null;
            };

            const usernameField = findField(usernameSelectors);
            const passwordField = findField(passwordSelectors);
            const submitButton = findField(submitSelectors);

            return {
                found: true,
                form: {
                    action: loginForm.action,
                    method: loginForm.method || 'GET',
                    id: loginForm.id || '',
                    className: loginForm.className || ''
                },
                usernameField: {
                    found: !!usernameField,
                    selector: usernameField ? usernameField.tagName.toLowerCase() +
                            (usernameField.id ? '#' + usernameField.id : '') +
                            (usernameField.className ? '.' + usernameField.className.split(' ').join('.') : '') : '',
                    name: usernameField ? usernameField.name || usernameField.id : '',
                    type: usernameField ? usernameField.type : '',
                    autocomplete: usernameField ? usernameField.autocomplete : ''
                },
                passwordField: {
                    found: !!passwordField,
                    selector: passwordField ? passwordField.tagName.toLowerCase() +
                            (passwordField.id ? '#' + passwordField.id : '') +
                            (passwordField.className ? '.' + passwordField.className.split(' ').join('.') : '') : '',
                    name: passwordField ? passwordField.name || passwordField.id : '',
                    autocomplete: passwordField ? passwordField.autocomplete : ''
                },
                submitButton: {
                    found: !!submitButton,
                    selector: submitButton ? submitButton.tagName.toLowerCase() +
                            (submitButton.id ? '#' + submitButton.id : '') +
                            (submitButton.className ? '.' + submitButton.className.split(' ').join('.') : '') : '',
                    text: submitButton ? submitButton.textContent.trim() : ''
                }
            };
        }
        """)

        if not login_form_info['found']:
            return {'success': False, 'message': '로그인 폼을 찾을 수 없습니다'}

        # 로그인 시도
        if (login_form_info['usernameField']['found'] and
            login_form_info['passwordField']['found']):

            # 사용자 이름 입력
            await mcp__playwright__browser_type(
                element="사용자 이름 필드",
                ref=login_form_info['usernameField']['selector'],
                text=username
            )

            # 비밀번호 입력
            await mcp__playwright__browser_type(
                element="비밀번호 필드",
                ref=login_form_info['passwordField']['selector'],
                text=password
            )

            # 로그인 버튼 클릭
            if login_form_info['submitButton']['found']:
                await mcp__playwright__browser_click(
                    element="로그인 버튼",
                    ref=login_form_info['submitButton']['selector']
                )

                # 로그인 결과 대기
                await mcp__playwright__browser_wait_for(
                    time=5,
                    text="",
                    textGone="로그인"
                )

                # 로그인 성공 여부 확인
                login_result = await mcp__playwright__browser_evaluate("""
                () => {
                    // 로그인 성공 지표들
                    const successIndicators = [
                        () => !document.querySelector('form'),
                        () => document.querySelector('.welcome, .dashboard, .user-info'),
                        () => document.body.textContent.includes('환영합니다') ||
                               document.body.textContent.includes('Welcome') ||
                               document.body.textContent.includes('로그아웃') ||
                               document.body.textContent.includes('Logout'),
                        () => window.location.href.includes('dashboard') ||
                               window.location.href.includes('welcome') ||
                               window.location.href.includes('home')
                    ];

                    for (const indicator of successIndicators) {
                        try {
                            if (indicator()) {
                                return {
                                    success: true,
                                    currentUrl: window.location.href,
                                    pageTitle: document.title
                                };
                            }
                        } catch (e) {
                            continue;
                        }
                    }

                    return {
                        success: false,
                        currentUrl: window.location.href,
                        pageTitle: document.title,
                        errorMessages: Array.from(document.querySelectorAll('.error, .alert, .message'))
                            .map(el => el.textContent.trim())
                    };
                }
                """)

                return {
                    'success': login_result['success'],
                    'form_info': login_form_info,
                    'login_result': login_result
                }

        return {'success': False, 'message': '로그인 필드를 찾을 수 없습니다'}

    except Exception as e:
        return {'success': False, 'error': str(e)}
```

### 8. 다중 페이지 크롤링 및 분석
```python
async def multi_page_analysis(base_url, max_pages=10, username=None, password=None):
    """다중 페이지 크롤링 및 보안 분석"""

    analysis_results = {
        base_url: base_url,
        pages_analyzed: [],
        total_vulnerabilities: {'high': [], 'medium': [], 'low': []},
        start_time: datetime.now().isoformat()
    }

    try:
        # 초기 페이지 접속
        await mcp__playwright__browser_navigate(base_url)

        # 로그인 필요시 처리
        if username and password:
            login_result = await automated_login_analysis(base_url, username, password)
            if login_result['success']:
                analysis_results['login_successful'] = True

        # 방문할 URL 목록 (BFS 방식)
        urls_to_visit = {base_url}
        visited_urls = set()

        page_count = 0
        while urls_to_visit and page_count < max_pages:
            current_url = urls_to_visit.pop()
            if current_url in visited_urls:
                continue

            visited_urls.add(current_url)

            # 페이지 접속
            await mcp__playwright__browser_navigate(current_url)

            # 페이지 분석
            page_analysis = await analyze_single_page()
            page_analysis['url'] = current_url
            page_analysis['timestamp'] = datetime.now().isoformat()

            analysis_results['pages_analyzed'].append(page_analysis)

            # 취약점 누적
            for severity in ['high', 'medium', 'low']:
                analysis_results['total_vulnerabilities'][severity].extend(
                    page_analysis.get('vulnerabilities', {}).get(severity, [])
                )

            # 새로운 링크 수집
            new_links = await extract_internal_links(current_url)
            for link in new_links:
                if link not in visited_urls and link not in urls_to_visit:
                    urls_to_visit.add(link)

            page_count += 1

        analysis_results['total_pages_analyzed'] = len(analysis_results['pages_analyzed'])
        analysis_results['end_time'] = datetime.now().isoformat()

        return analysis_results

    except Exception as e:
        analysis_results['error'] = str(e)
        return analysis_results

async def analyze_single_page():
    """단일 페이지 분석"""

    # 모든 분석 함수를 병렬로 실행
    tasks = [
        collect_basic_site_info(),
        analyze_security_headers(),
        analyze_forms_detailed(),
        analyze_navigation_structure(),
        analyze_storage_and_cookies(),
        analyze_javascript_and_dynamic_content()
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    page_analysis = {
        'basic_info': results[0] if not isinstance(results[0], Exception) else {'error': str(results[0])},
        'security': results[1] if not isinstance(results[1], Exception) else {'error': str(results[1])},
        'forms': results[2] if not isinstance(results[2], Exception) else {'error': str(results[2])},
        'navigation': results[3] if not isinstance(results[3], Exception) else {'error': str(results[3])},
        'storage': results[4] if not isinstance(results[4], Exception) else {'error': str(results[4])},
        'javascript': results[5] if not isinstance(results[5], Exception) else {'error': str(results[5])}
    }

    # 취약점 요약
    page_analysis['vulnerabilities'] = summarize_page_vulnerabilities(page_analysis)

    return page_analysis

async def extract_internal_links(base_url):
    """내부 링크 추출"""

    links = await mcp__playwright__browser_evaluate(f"""
    () => {{
        const baseUrl = '{base_url}';
        const baseDomain = new URL(baseUrl).hostname;
        const internalLinks = new Set();

        document.querySelectorAll('a[href]').forEach(link => {{
            try {{
                const href = link.href;
                if (href.startsWith('http://') || href.startsWith('https://')) {{
                    const url = new URL(href);
                    if (url.hostname === baseDomain) {{
                        // 같은 도메인의 링크만 수집
                        internalLinks.add(href);
                    }}
                }}
            }} catch (e) {{
                // 무효한 URL은 무시
            }}
        }});

        return Array.from(internalLinks);
    }}
    """)

    return links

def summarize_page_vulnerabilities(page_analysis):
    """페이지 분석 결과에서 취약점 요약"""

    vulnerabilities = {'high': [], 'medium': [], 'low': []}

    # 보안 관련 취약점
    security = page_analysis.get('security', {})

    if not security.get('isHTTPS', True):
        vulnerabilities['high'].append('HTTP 프로토콜 사용')

    if security.get('totalHTTPResources', 0) > 0:
        vulnerabilities['medium'].append(f'Mixed Content: {security["totalHTTPResources"]}개')

    # 폼 관련 취약점
    forms = page_analysis.get('forms', [])
    for form in forms:
        if form.get('method') === 'GET':
            for field in form.get('fields', []):
                if field.get('isPassword'):
                    vulnerabilities['high'].append('비밀번호 전송에 GET 방식 사용')

        # 폼의 잠재적 취약점
        for vuln in form.get('potentialVulnerabilities', []):
            severity = vuln.get('severity', 'medium').lower()
            if severity in vulnerabilities:
                vulnerabilities[severity].append(vuln.get('type', 'Unknown vulnerability'))

    # 스토리지 관련 취약점
    storage = page_analysis.get('storage', {})
    if storage.get('sensitiveData'):
        for sensitive in storage['sensitiveData']:
            vulnerabilities['medium'].append(f'민감정보 {sensitive["container"]} 저장: {sensitive["key"]}')

    # JavaScript 관련 취약점
    js = page_analysis.get('javascript', {})
    if js.get('consoleLogFound'):
        vulnerabilities['low'].append('디버깅 정보 노출 가능성')

    if js.get('inlineScripts', {}).get('withSensitiveData', 0) > 0:
        vulnerabilities['medium'].append('인라인 스크립트에 민감정보 포함')

    return vulnerabilities
```

## 스크린샷 및 시각적 분석

### 자동 스크린샷 생성
```python
async def generate_visual_analysis_screenshots(base_url, output_dir="./screenshots"):
    """시각적 분석을 위한 스크린샷 자동 생성"""

    screenshots = []

    try:
        # 메인 페이지 스크린샷
        await mcp__playwright__browser_navigate(base_url)
        main_screenshot = f"{output_dir}/main_page.png"
        await mcp__playwright__browser_take_screenshot(
            type="png",
            filename=main_screenshot,
            element="메인 페이지",
            ref="",
            fullPage=True
        )
        screenshots.append({"type": "main_page", "file": main_screenshot})

        # 로그인 페이지 스크린샷
        login_screenshot = f"{output_dir}/login_form.png"
        await mcp__playwright__browser_take_screenshot(
            type="png",
            filename=login_screenshot,
            element="로그인 폼",
            ref="form",
            fullPage=False
        )
        screenshots.append({"type": "login_form", "file": login_screenshot})

        # 내비게이션 메뉴 스크린샷
        nav_screenshot = f"{output_dir}/navigation.png"
        await mcp__playwright__browser_take_screenshot(
            type="png",
            filename=nav_screenshot,
            element="내비게이션 메뉴",
            ref="nav, .navigation, .nav",
            fullPage=False
        )
        screenshots.append({"type": "navigation", "file": nav_screenshot})

        return screenshots

    except Exception as e:
        return {"error": str(e), "screenshots": screenshots}
```

이 가이드를 사용하면 Playwright MCP 서버를 활용하여 체계적이고 자동화된 웹사이트 보안 분석을 수행할 수 있다.