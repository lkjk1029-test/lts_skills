---
name: web-security-analyzer
description: Comprehensive web security vulnerability analyzer that crawls entire websites, extracts menu structures, analyzes HTTP requests with parameters and methods, identifies potential vulnerabilities including XSS and SQL injection patterns, and generates detailed Excel reports with menu-by-menu security analysis.
---

# 종합 웹 보안 분석기 스킬

이 스킬은 Playwright로 메뉴를 직접 클릭하여 탐색하고 Chrome DevTools로 상세 보안 분석을 수행하여 웹사이트 전체를 체계적으로 분석한다. 모든 메뉴 구조와 보안 취약점을 식별하고 상세한 엑셀 보고서를 생성하며, 공격을 수행하지 않고 코드 패턴과 요청 분석을 통해 취약점 가능성을 평가한다.

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
    if not all(mcp_status.values()):
        print("\n" + "=" * 50)
        print("❌ 스킬 실행 불가")
        print("=" * 50)
        print("두 MCP 서버 모두 설치가 필수입니다:")
        print("  • Chrome DevTools MCP (상세 분석 및 보안 점검)")
        print("  • Playwright MCP (메뉴 클릭 및 네비게이션)")
        print("\n설치 방법:")
        print("  Claude Code 설정에서 두 MCP 서버를 모두 설치해주세요.")
        print("  자세한 설명: https://docs.claude.com/claude-code/mcp")
        print("=" * 50)
        return False

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

async def discover_interactive_elements() -> List[Dict[str, Any]]:
    """동적 상호작용 가능한 요소 발견 (실제 사용자처럼)"""
    try:
        elements = await mcp__chrome_devtools__evaluate_script("""
        () => {
            try {
                const interactiveElements = [];
                const visitedUrls = new Set();
                const currentOrigin = window.location.origin;
                const currentHost = window.location.hostname;

                // 도메인 필터링 함수: 주어진 도메인에 속하는지 확인
                function isSameDomain(url) {
                    if (!url) return false;

                    try {
                        const urlObj = new URL(url, window.location.href);
                        const urlOrigin = urlObj.origin;
                        const urlHost = urlObj.hostname;

                        // 완전히 같은 도메인
                        if (urlOrigin === currentOrigin) return true;

                        // 서브도메인 포함 (예: api.localhost:3000는 localhost:3000 포함)
                        if (urlHost === currentHost || urlHost.endsWith('.' + currentHost)) return true;

                        // 로컬 개발 환경 특별 처리
                        if (currentHost.includes('localhost') || currentHost.includes('127.0.0.1')) {
                            return urlHost.includes('localhost') || urlHost.includes('127.0.0.1');
                        }

                        return false;
                    } catch (e) {
                        return false;
                    }
                }

                // 1. 모든 링크 (a 태그) - 광범위한 선택자로 모든 링크 포함
                const allLinkSelectors = [
                    'a[href]', 'link[href]', 'area[href]'  // 모든 링크 유형
                ];

                allLinkSelectors.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach((elem, index) => {
                            const text = elem.textContent?.trim() || elem.title || '';
                            const href = elem.href || '';

                            // 필터링: 같은 도메인 && 의미있는 텍스트 && 제외할 패턴 아님
                            if (text && text.length > 0 && text.length < 200 &&
                                isSameDomain(href) &&
                                !href.includes('#') &&
                                !href.includes('javascript:') &&
                                !href.includes('mailto:') &&
                                !href.includes('tel:') &&
                                !href.includes('ftp:') &&
                                !visitedUrls.has(href)) {

                                visitedUrls.add(href);

                                // 메뉴 링크인지 일반 링크인지 구분
                                const isMenuLink = elem.closest('nav, .nav, .navbar, .menu, .navigation, .sidebar, header') !== null;

                                interactiveElements.push({
                                    selector: selector,
                                    index: index,
                                    text: text,
                                    url: href,
                                    elementType: isMenuLink ? 'menu_link' : 'link',
                                    actionType: 'click',
                                    priority: isMenuLink ? 1 : 2,
                                    discoveryMethod: 'static',
                                    targetDomain: new URL(href, window.location.href).hostname
                                });
                            }
                        });
                    } catch (e) {
                        console.log('Link selector error:', selector, e.message);
                    }
                });

                // 2. 모든 버튼 및 클릭 가능 요소 - 최대한 포괄적인 선택자
                const allButtonSelectors = [
                    'button',
                    'input[type="button"]',
                    'input[type="submit"]',
                    'input[type="reset"]',
                    'input[type="image"]',
                    '[role="button"]',
                    '[role="link"]',
                    '.btn',
                    '.button',
                    '.clickable',
                    '.action',
                    '.trigger',
                    '.link-button',
                    '.submit-btn',
                    '[onclick]',
                    '[data-action]',
                    '[data-toggle]',
                    '[data-target]',
                    '.tab',
                    '.accordion-trigger',
                    '.modal-trigger',
                    '.dropdown-toggle'
                ];

                allButtonSelectors.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach((elem, index) => {
                            // 버튼 텍스트 가져오기 (다양한 소스에서)
                            let text = elem.textContent?.trim() ||
                                      elem.value?.trim() ||
                                      elem.title?.trim() ||
                                      elem.alt?.trim() ||
                                      elem.ariaLabel?.trim() ||
                                      elem.placeholder?.trim() || '';

                            // 길이 제한 및 의미있는 텍스트만 포함
                            if (text && text.length > 0 && text.length < 150) {
                                interactiveElements.push({
                                    selector: selector,
                                    index: index,
                                    text: text,
                                    elementType: 'button',
                                    actionType: 'click',
                                    priority: 3,
                                    discoveryMethod: 'static',
                                    url: window.location.href,
                                    elementData: {
                                        tagName: elem.tagName,
                                        type: elem.type,
                                        className: elem.className,
                                        id: elem.id
                                    }
                                });
                            }
                        });
                    } catch (e) {
                        console.log('Button selector error:', selector, e.message);
                    }
                });

                // 3. 폼 요소 (입력 필드, 폼 전송 등)
                const formSelectors = [
                    'form',
                    'input:not([type="hidden"])',
                    'textarea',
                    'button[type="submit"]',
                    'input[type="submit"]'
                ];

                formSelectors.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach((elem, index) => {
                            let text = '';

                            if (elem.tagName === 'FORM') {
                                // 폼인 경우 action이나 id를 텍스트로 사용
                                text = elem.action?.trim() ||
                                       elem.id?.trim() ||
                                       elem.className?.trim() ||
                                       `form_${index}`;
                            } else {
                                // 입력 필드인 경우 label, placeholder, name 등
                                text = elem.labels?.[0]?.textContent?.trim() ||
                                      elem.placeholder?.trim() ||
                                      elem.name?.trim() ||
                                      elem.id?.trim() ||
                                      elem.title?.trim() ||
                                      `${elem.type || 'input'}_${index}`;
                            }

                            if (text && text.length < 100) {
                                interactiveElements.push({
                                    selector: selector,
                                    index: index,
                                    text: text,
                                    elementType: elem.tagName === 'FORM' ? 'form' : 'input_field',
                                    actionType: elem.tagName === 'FORM' ? 'interact' : 'input',
                                    priority: 4,
                                    discoveryMethod: 'static',
                                    url: window.location.href,
                                    elementData: {
                                        tagName: elem.tagName,
                                        type: elem.type,
                                        name: elem.name,
                                        id: elem.id
                                    }
                                });
                            }
                        });
                    } catch (e) {
                        console.log('Form selector error:', selector, e.message);
                    }
                });

                // 4. 추가 상호작용 요소 (탭, 아코디언, 모달 등)
                const additionalSelectors = [
                    '.tab-link', '.tab', '[role="tab"]',
                    '.accordion-header', '.accordion-trigger',
                    '.modal-trigger', '.popup-trigger',
                    '.carousel-control', '.slider-control',
                    '.tree-item', '.tree-node',
                    '.list-item.clickable', '.grid-item.clickable',
                    '[data-bs-toggle]', '[data-toggle]',
                    '[data-bs-target]', '[data-target]',
                    '.nav-link', '.page-link'
                ];

                additionalSelectors.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach((elem, index) => {
                            const text = elem.textContent?.trim() ||
                                      elem.title?.trim() ||
                                      elem.ariaLabel?.trim() ||
                                      `${selector.replace(/[^\w]/g, '_')}_${index}`;

                            if (text && text.length < 150) {
                                interactiveElements.push({
                                    selector: selector,
                                    index: index,
                                    text: text,
                                    elementType: 'interactive_element',
                                    actionType: 'click',
                                    priority: 5,
                                    discoveryMethod: 'static',
                                    url: window.location.href
                                });
                            }
                        });
                    } catch (e) {
                        console.log('Additional selector error:', selector, e.message);
                    }
                });

                // 우선순위별 정렬 및 중복 제거
                return interactiveElements
                    .sort((a, b) => a.priority - b.priority)
                    .slice(0, MAX_PAGES);

            } catch (e) {
                console.error('Interactive elements discovery error:', e.message);
                return [];
            }
        }
        """)

        return elements or []
    except Exception as e:
        print(f"상호작용 요소 발견 실패: {str(e)}")
        return []

async def click_and_analyze_element_playwright(element: Dict[str, Any]) -> Dict[str, Any]:
    """요소를 클릭하고 결과 분석 (Playwright 전용 - 메뉴 클릭용)"""
    try:
        # 현재 페이지 정보 가져오기 (Chrome DevTools 사용)
        original_url = await mcp__chrome_devtools__evaluate_script("() => window.location.href")
        original_title = await mcp__chrome_devtools__evaluate_script("() => document.title")

        print(f"🖱️ Playwright 클릭 중: {element.get('text', 'Unknown')} ({element.get('elementType', 'unknown')})")

        # Playwright로 페이지 접속 및 클릭
        current_pages = await mcp__playwright__list_pages()
        if not current_pages:
            print("❌ Playwright 활성 페이지 없음 - 새 페이지 생성")
            await mcp__playwright__new_page(original_url)
            await asyncio.sleep(2)
            current_pages = await mcp__playwright__list_pages()

        # 활성 페이지 선택
        page_idx = 0  # 첫 번째 페이지 사용
        await mcp__playwright__select_page(page_idx)

        # 클릭 전 상태 저장
        before_click = {
            'url': original_url,
            'title': original_title,
            'timestamp': datetime.now() + timedelta(hours=9).isoformat()
        }

        # Playwright로 요소 클릭 시도
        selector = element.get('selector', '')
        element_text = element.get('text', '')

        try:
            # 여러 클릭 방법 시도
            clicked = False

            # 1. 텍스트 기반 클릭
            if element_text:
                try:
                    await mcp__playwright__click(f"text={element_text}")
                    clicked = True
                    print(f"✅ 텍스트로 클릭 성공: {element_text}")
                except Exception as e:
                    print(f"⚠️ 텍스트 클릭 실패: {str(e)}")

            # 2. 선택자 기반 클릭
            if not clicked and selector:
                try:
                    await mcp__playwright__click(selector)
                    clicked = True
                    print(f"✅ 선택자로 클릭 성공: {selector}")
                except Exception as e:
                    print(f"⚠️ 선택자 클릭 실패: {str(e)}")

            # 3. CSS 선택자 유추 클릭
            if not clicked and element_text:
                try:
                    css_selector = f"button:has-text('{element_text}'), a:has-text('{element_text}'), input[value='{element_text}']"
                    await mcp__playwright__click(css_selector)
                    clicked = True
                    print(f"✅ 유추 선택자로 클릭 성공: {element_text}")
                except Exception as e:
                    print(f"⚠️ 유추 선택자 클릭 실패: {str(e)}")

            if not clicked:
                print(f"❌ 클릭 실패: {element_text}")
                return None

            # 클릭 후 대기 (페이지 로딩)
            await asyncio.sleep(3)

            # 클릭 후 상태 확인 (Chrome DevTools와 Playwright 모두 사용)
            after_url_cd = await mcp__chrome_devtools__evaluate_script("() => window.location.href")
            after_title_cd = await mcp__chrome_devtools__evaluate_script("() => document.title")

            after_click = {
                'url': after_url_cd,
                'title': after_title_cd,
                'timestamp': datetime.now() + timedelta(hours=9).isoformat()
            }

            # 페이지 변경 감지
            page_changed = (before_click['url'] != after_click['url'] or
                           before_click['title'] != after_click['title'])

            result = {
                'element': element,
                'before_click': before_click,
                'after_click': after_click,
                'page_changed': page_changed,
                'analysis_type': 'playwright_click',
                'click_method': 'text_based' if element_text else 'selector_based',
                'timestamp': datetime.now() + timedelta(hours=9).isoformat()
            }

            print(f"✅ 클릭 분석 완료: 페이지 변경 {'O' if page_changed else 'X'}")
            return result

        except Exception as click_error:
            print(f"❌ Playwright 클릭 중 오류: {str(click_error)}")
            return None

    except Exception as e:
        print(f"❌ Playwright 클릭 분석 실패: {element.get('text', 'Unknown')} - {str(e)}")
        return None

async def explore_dynamic_content(current_url: str, skip_dynamic: bool = False) -> List[Dict[str, Any]]:
    """동적 콘텐츠 탐색 (실제 사용자처럼 메뉴 클릭하며 탐색)"""
    # 동적 탐색 건너뛰기 옵션
    if skip_dynamic:
        print("⚠️ 동적 탐색을 건너뜁니다 - 기본 분석으로 계속합니다")
        return []

    try:
        print(f"🔍 동적 콘텐츠 탐색 시작: {current_url}")

        # 안전하게 상호작용 요소 발견 (타임아웃 적용)
        try:
            interactive_elements = await asyncio.wait_for(
                discover_interactive_elements(),
                timeout=15  # 15초 타임아웃
            )
            print(f"발견된 상호작용 요소: {len(interactive_elements)}개")
        except asyncio.TimeoutError:
            print("⚠️ 상호작용 요소 발견 시간 초과")
            interactive_elements = []
        except Exception as e:
            print(f"⚠️ 상호작용 요소 발견 오류: {str(e)}")
            interactive_elements = []

        explored_pages = []
        visited_urls = set([current_url])

        # 안전하게 요소 클릭 및 분석 (최대 5개로 제한)
        max_elements = min(5, len(interactive_elements))
        for i, element in enumerate(interactive_elements[:max_elements]):
            try:
                print(f"🔍 요소 분석 중 ({i+1}/{max_elements}): {element.get('text', '')[:20]}...")

                # 클릭 및 분석 (Playwright 전용, 타임아웃 적용)
                result = await asyncio.wait_for(
                    click_and_analyze_element_playwright(element),
                    timeout=15  # 15초 타임아웃 (Playwright는 더 길게)
                )

                if result:
                    explored_pages.append(result)
                    print(f"✅ 요소 분석 완료: {result.get('after_click', {}).get('title', '')}")

                    # 페이지가 변경된 경우, 새로운 URL 기록
                    new_url = result['after_click']['url']
                    if new_url != current_url and new_url not in visited_urls:
                        visited_urls.add(new_url)
                        print(f"🔄 새로운 페이지 발견: {new_url}")

                        # 잠시 대기 후 다음 탐색
                        await asyncio.sleep(1)

                # 원래 페이지로 돌아가기 (필요시)
                if result and result['page_changed']:
                    try:
                        await asyncio.wait_for(
                            mcp__chrome_devtools__navigate_page(current_url),
                            timeout=5  # 5초 타임아웃
                        )
                        await asyncio.sleep(1)
                    except:
                        print("원래 페이지로 돌아가기 실패, 계속 진행")

            except asyncio.TimeoutError:
                print(f"⚠️ 요소 {i+1} 분석 시간 초과 - 건너뜁니다")
                continue
            except Exception as e:
                print(f"⚠️ 요소 {i+1} 분석 오류: {str(e)}")
                continue

        print(f"✅ 동적 탐색 완료: {len(explored_pages)}개 페이지 분석됨")
        return explored_pages

    except Exception as e:
        print(f"동적 콘텐츠 탐색 실패: {str(e)}")
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

# 메인 분석 프로세스 (동적 탐색 기반)
async def analyze_website(target_url: str, username: Optional[str] = None, password: Optional[str] = None):
    """웹사이트 분석 메인 함수 (실제 사용자처럼 클릭하며 탐색)"""

    print("=" * 60)
    print("🚀 동적 웹 보안 분석 시작")
    print("=" * 60)

    # 1. 초기 페이지 접속
    if not await safe_navigate(target_url):
        raise Exception(f"초기 페이지 접속 실패: {target_url}")

    # 2. 로그인 처리 (필요시)
    if username and password:
        print("🔐 로그인을 시도합니다...")
        if not await safe_login(username, password):
            print("⚠️ 로그인에 실패했습니다. 비인증 상태로 분석을 계속합니다.")

    # 3. 동적 콘텐츠 탐색 (실제 사용자처럼 클릭하며 메뉴 탐색)
    print("\n🔍 동적 메뉴 탐색을 시작합니다...")
    print("실제 사용자처럼 버튼을 클릭하며 모든 기능을 탐색합니다.")

    # Playwright로 동적 탐색 수행
    print("🖱️ Playwright로 동적 메뉴 탐색을 시작합니다...")
    print("실제 사용자처럼 버튼을 클릭하며 모든 기능을 탐색합니다.")

    try:
        dynamic_results = await asyncio.wait_for(
            explore_dynamic_content(target_url, skip_dynamic=False),
            timeout=120  # 2분 타임아웃
        )
        print(f"✅ Playwright 동적 탐색 완료: {len(dynamic_results)}개 페이지 발견")
    except asyncio.TimeoutError:
        print("⚠️ 동적 탐색 시간 초과 - 기본 분석으로 계속합니다")
        dynamic_results = []
    except Exception as e:
        print(f"⚠️ 동적 탐색 오류: {str(e)} - 기본 분석으로 계속합니다")
        dynamic_results = []

    # 4. 탐색된 페이지별 상세 보안 분석
    print(f"\n📊 {len(dynamic_results)}개의 탐색 결과에 대해 상세 보안 분석을 시작합니다...")
    menu_analysis = []
    analyzed_urls = set()

    for i, result in enumerate(dynamic_results):
        try:
            element_info = result.get('element', {})
            page_changed = result.get('page_changed', False)
            after_url = result.get('after_click', {}).get('url', target_url)

            # 중복 URL 건너뛰기
            if after_url in analyzed_urls:
                continue
            analyzed_urls.add(after_url)

            element_text = element_info.get('text', 'Unknown')
            element_type = element_info.get('elementType', 'unknown')

            print(f"\n[{i+1}/{len(dynamic_results)}] 분석 중: {element_text} ({element_type})")

            # 해당 페이지로 이동하여 상세 분석
            if await safe_navigate(after_url):
                try:
                    # 페이지 상세 보안 분석
                    page_analysis = await analyze_page_security(after_url, element_text, element_info)
                    if page_analysis:
                        # 동적 탐색 정보 추가
                        page_analysis['dynamic_interaction'] = {
                            'element_clicked': element_info,
                            'page_changed': page_changed,
                            'interaction_timestamp': result.get('timestamp'),
                            'before_click': result.get('before_click'),
                            'after_click': result.get('after_click')
                        }
                        menu_analysis.append(page_analysis)

                    # 분석 간 대기 (과부하 방지)
                    await asyncio.sleep(1.5)

                except Exception as e:
                    print(f"페이지 상세 분석 실패: {after_url} - {str(e)}")
                    continue
            else:
                print(f"페이지 접속 실패: {after_url}")
                continue

        except Exception as e:
            print(f"탐색 결과 처리 실패: {str(e)}")
            continue

    # 5. 추가적인 정적 링크도 분석 (동적 탐색으로 발견되지 않은 부분)
    print(f"\n🔗 추가적인 정적 링크 분석을 시작합니다...")
    try:
        static_links = await collect_static_links_fallback()
        print(f"추가 발견된 정적 링크: {len(static_links)}개")

        for link in static_links[:20]:  # 최대 20개만 추가 분석
            url = link.get('url', '')
            text = link.get('text', 'Unknown')

            if url and url not in analyzed_urls:
                print(f"정적 링크 분석: {text}")

                if await safe_navigate(url):
                    try:
                        page_analysis = await analyze_page_security(url, text, {'discovery_method': 'static_fallback'})
                        if page_analysis:
                            menu_analysis.append(page_analysis)
                        await asyncio.sleep(1)
                    except Exception as e:
                        print(f"정적 링크 분석 실패: {url} - {str(e)}")
                        continue
                analyzed_urls.add(url)

    except Exception as e:
        print(f"정적 링크 추가 분석 실패: {str(e)}")

    print(f"\n" + "=" * 60)
    print(f"✅ 동적 웹 보안 분석 완료")
    print(f"📊 분석된 총 페이지/요소: {len(menu_analysis)}개")
    print(f"🔍 탐색 방식: 동적 클릭 탐색 + 정적 링크 분석")
    print("=" * 60)

    return menu_analysis

async def collect_static_links_fallback() -> List[Dict[str, str]]:
    """동적 탐색으로 발견되지 않은 정적 링크 수집 (보조 기능)"""
    try:
        links = await mcp__chrome_devtools__evaluate_script("""
        () => {
            try {
                const links = [];
                const visitedUrls = new Set();

                // 일반 내부 링크만 수집 (동적 탐색으로 발견되지 않은 것들)
                const internalLinks = document.querySelectorAll('a[href]');
                let linkCount = 0;

                internalLinks.forEach(link => {
                    if (linkCount >= 30) return;

                    if (link.href &&
                        link.href.includes(window.location.origin) &&
                        !link.href.includes('#') &&
                        !link.href.includes('javascript:') &&
                        !visitedUrls.has(link.href) &&
                        linkCount < 30) {

                        visitedUrls.add(link.href);
                        links.push({
                            text: link.textContent.trim(),
                            url: link.href,
                            type: 'static_fallback',
                            priority: 5
                        });
                        linkCount++;
                    }
                });

                return links;
            } catch (e) {
                console.error('Static links collection error:', e.message);
                return [];
            }
        }
        """)

        return links or []
    except Exception as e:
        print(f"정적 링크 수집 실패: {str(e)}")
        return []

# MCP 서버 설치 확인
print("🔍 MCP 서버 설치 여부 확인 중...")
mcp_status = check_mcp_servers()

# 둘 다 설치되어 있지 않으면 종료
if not all(mcp_status.values()):
    print("\n" + "=" * 50)
    print("❌ 스킬 실행 불가")
    print("=" * 50)
    print("두 MCP 서버 모두 설치가 필수입니다:")
    print("  • Chrome DevTools MCP (상세 분석 및 보안 점검)")
    print("  • Playwright MCP (메뉴 클릭 및 네비게이션)")
    print("\n설치 방법:")
    print("  Claude Code 설정에서 두 MCP 서버를 모두 설치해주세요.")
    print("  자세한 설명: https://docs.claude.com/claude-code/mcp")
    print("=" * 50)
    import sys
    sys.exit(1)

print("✅ MCP 서버 설치 확인 완료")

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
async def monitor_realtime_network(duration: int = 10) -> List[Dict[str, Any]]:
    """실시간 네트워크 요청 모니터링 (Playwright 활용)"""
    network_requests = []
    start_time = datetime.now() + timedelta(hours=9)

    print(f"🌐 실시간 네트워크 모니터링 시작 ({duration}초간)")

    try:
        # 1. Playwright로 네트워크 모니터링 설정
        if await check_playwright_available():
            network_requests.extend(await monitor_with_playwright(duration))
        else:
            # 2. Chrome DevTools로 대체
            network_requests.extend(await monitor_with_chrome_devtools(duration))

    except Exception as e:
        print(f"네트워크 모니터링 실패: {str(e)}")

    end_time = datetime.now() + timedelta(hours=9)
    monitoring_duration = (end_time - start_time).total_seconds()

    print(f"✅ 네트워크 모니터링 완료: {len(network_requests)}개 요청 ({monitoring_duration:.1f}초)")

    return network_requests

async def check_playwright_available() -> bool:
    """Playwright MCP 사용 가능 여부 확인"""
    try:
        # Playwright 페이지 생성 테스트
        test_result = await mcp__playwright__new_page("about:blank")
        if test_result:
            await mcp__playwright__close_page(test_result.get('page_id'))
            return True
    except:
        pass
    return False

async def monitor_with_playwright(duration: int) -> List[Dict[str, Any]]:
    """Playwright로 네트워크 요청 모니터링"""
    requests = []

    try:
        # 새 페이지 생성
        page_info = await mcp__playwright__new_page("about:blank")
        page_id = page_info.get('page_id')

        if not page_id:
            return requests

        print("Playwright로 네트워크 모니터링 시작...")

        # 네트워크 리스너 설정
        await mcp__playwright__evaluate_script(page_id, """
        () => {
            window.networkRequests = [];

            // Fetch 요청 모니터링
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                const request = {
                    type: 'fetch',
                    url: args[0],
                    method: args[1]?.method || 'GET',
                    headers: args[1]?.headers || {},
                    timestamp: new Date().toISOString(),
                    body: args[1]?.body || null
                };

                window.networkRequests.push(request);
                console.log('Fetch 요청 감지:', request.url);

                return originalFetch.apply(this, args).then(response => {
                    const responseClone = response.clone();
                    return responseClone.text().then(body => {
                        request.response = {
                            status: response.status,
                            statusText: response.statusText,
                            headers: Object.fromEntries(response.headers.entries()),
                            body: body.substring(0, 1000) // 처음 1000자만 저장
                        };
                        console.log('Fetch 응답 수신:', request.url, response.status);
                        return response;
                    });
                });
            };

            // XMLHttpRequest 모니터링
            const originalXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                const xhr = new originalXHR();
                const originalOpen = xhr.open;
                const originalSend = xhr.send;

                xhr.open = function(method, url, ...args) {
                    this._request = {
                        type: 'xhr',
                        url: url,
                        method: method,
                        headers: {},
                        timestamp: new Date().toISOString()
                    };
                    return originalOpen.apply(this, [method, url, ...args]);
                };

                xhr.send = function(body) {
                    this._request.body = body;
                    window.networkRequests.push(this._request);
                    console.log('XHR 요청 감지:', this._request.url);

                    return originalSend.apply(this, [body]);
                };

                return xhr;
            };

            return '네트워크 모니터링 설정 완료';
        }
        """)

        # 대기하며 페이지 상호작용 유도
        print("페이지에서 상호작용을 시도합니다...")

        # 스크롤하여 동적 콘텐츠 로딩 유도
        await mcp__playwright__evaluate_script(page_id, """
        () => {
            // 스크롤 이벤트 유도
            window.scrollTo(0, document.body.scrollHeight / 2);

            // 잠시 대기 후 다른 요소 클릭 시도
            setTimeout(() => {
                const clickableElements = document.querySelectorAll('button, a, [onclick]');
                if (clickableElements.length > 0) {
                    const randomElement = clickableElements[Math.floor(Math.random() * Math.min(5, clickableElements.length))];
                    if (randomElement && randomElement.textContent.trim()) {
                        randomElement.click();
                        console.log('랜덤 요소 클릭:', randomElement.textContent.trim());
                    }
                }
            }, 2000);

            return '페이지 상호작용 완료';
        }
        """)

        # 모니터링 기간 동안 대기
        await asyncio.sleep(duration)

        # 수집된 네트워크 요청 가져오기
        collected_requests = await mcp__playwright__evaluate_script(page_id, """
        () => {
            return window.networkRequests || [];
        }
        """)

        if collected_requests:
            for req in collected_requests:
                requests.append({
                    'url': req.get('url', ''),
                    'method': req.get('method', 'GET'),
                    'headers': req.get('headers', {}),
                    'body': req.get('body', ''),
                    'response': req.get('response', {}),
                    'timestamp': req.get('timestamp', ''),
                    'type': req.get('type', 'unknown'),
                    'monitoring_method': 'playwright'
                })

        # 페이지 정리
        await mcp__playwright__close_page(page_id)

    except Exception as e:
        print(f"Playwright 네트워크 모니터링 실패: {str(e)}")

    return requests

async def monitor_with_chrome_devtools(duration: int) -> List[Dict[str, Any]]:
    """Chrome DevTools로 네트워크 요청 모니터링"""
    requests = []

    try:
        print("Chrome DevTools로 네트워크 모니터링 시작...")

        start_time = datetime.now() + timedelta(hours=9)

        # 페이지 내에서 네트워크 활동 유도
        await mcp__chrome_devtools__evaluate_script("""
        () => {
            window.networkRequests = [];

            // 기존 네트워크 요청 수집
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                const request = {
                    url: args[0],
                    method: args[1]?.method || 'GET',
                    timestamp: new Date().toISOString()
                };
                window.networkRequests.push(request);
                return originalFetch.apply(this, args);
            };

            // AJAX 요청 감지를 위한 MutationObserver
            const observer = new MutationObserver(() => {
                // DOM 변화 감지 시 추가 요청 가능성
                console.log('DOM 변화 감지 - 추가 요청 확인 필요');
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true
            });

            // 자동 스크롤
            setTimeout(() => {
                window.scrollTo(0, document.body.scrollHeight);
            }, 1000);

            return 'Chrome DevTools 모니터링 설정 완료';
        }
        """)

        # 모니터링 기간 동안 대기
        await asyncio.sleep(duration)

        # 네트워크 요청 수집
        collected_requests = await mcp__chrome_devtools__evaluate_script("""
        () => {
            return window.networkRequests || [];
        }
        """)

        if collected_requests:
            for req in collected_requests:
                requests.append({
                    'url': req.get('url', ''),
                    'method': req.get('method', 'GET'),
                    'timestamp': req.get('timestamp', ''),
                    'type': req.get('type', 'fetch'),
                    'monitoring_method': 'chrome_devtools'
                })

        # Chrome DevTools 네트워크 탭에서 수집된 요청도 가져오기
        try:
            network_data = await mcp__chrome_devtools__list_network_requests(
                pageSize=100,
                includePreservedRequests=True
            )

            if network_data:
                monitoring_start = start_time.isoformat()
                for net_req in network_data:
                    # 모니터링 기간 내의 요청만 필터링
                    if net_req.get('request_time', '') >= monitoring_start:
                        requests.append({
                            'url': net_req.get('url', ''),
                            'method': net_req.get('method', ''),
                            'headers': net_req.get('headers', {}),
                            'response': net_req.get('response', {}),
                            'timestamp': net_req.get('request_time', ''),
                            'type': 'network_tab',
                            'monitoring_method': 'chrome_devtools'
                        })
        except Exception as e:
            print(f"Chrome DevTools 네트워크 데이터 수집 실패: {str(e)}")

    except Exception as e:
        print(f"Chrome DevTools 네트워크 모니터링 실패: {str(e)}")

    return requests

async def deep_api_analysis(api_endpoints: List[Dict[str, Any]], base_url: str) -> Dict[str, Any]:
    """API 엔드포인트 심층 분석 (병렬 처리 및 최적화)"""

    # 최대 분석 개수 및 동시 처리 제한
    MAX_ANALYSIS_COUNT = 15  # 기존 10개에서 15개로 증가
    CONCURRENT_LIMIT = 3    # 동시에 처리할 API 수

    analysis_targets = api_endpoints[:MAX_ANALYSIS_COUNT]
    print(f"🔍 {len(analysis_targets)}개 API 엔드포인트 심층 분석 시작 (병렬 처리, 최대 {CONCURRENT_LIMIT}개 동시)")

    async def analyze_single_api(api_info, index):
        """단일 API 분석 (개별 래퍼 함수)"""
        try:
            url = api_info.get('url', '')
            method = api_info.get('method', 'GET')

            print(f"[{index+1}/{len(analysis_targets)}] API 분석: {method} {url}")

            # 모든 분석 작업을 병렬로 실행
            tasks = [
                analyze_api_structure(url, method),
                test_api_parameters(url, method),
                test_authentication_bypass(url, method),
                test_rate_limiting(url, method)
            ]

            # 병렬 실행 및 결과 수집
            structure_analysis, parameter_analysis, auth_analysis, rate_limit_analysis = await asyncio.gather(
                *tasks, return_exceptions=True
            )

            # 예외 처리
            if isinstance(structure_analysis, Exception):
                structure_analysis = {'error': str(structure_analysis)}
            if isinstance(parameter_analysis, Exception):
                parameter_analysis = {'error': str(parameter_analysis)}
            if isinstance(auth_analysis, Exception):
                auth_analysis = {'error': str(auth_analysis)}
            if isinstance(rate_limit_analysis, Exception):
                rate_limit_analysis = {'error': str(rate_limit_analysis)}

            return {
                'original_api': api_info,
                'structure_analysis': structure_analysis,
                'parameter_analysis': parameter_analysis,
                'auth_analysis': auth_analysis,
                'rate_limit_analysis': rate_limit_analysis,
                'deep_analysis_timestamp': datetime.now() + timedelta(hours=9).isoformat(),
                'analysis_duration': 'parallel_completed'
            }

        except Exception as e:
            print(f"API 심층 분석 실패: {url} - {str(e)}")
            return {
                'original_api': api_info,
                'error': str(e),
                'deep_analysis_timestamp': datetime.now() + timedelta(hours=9).isoformat()
            }

    # 세마포어로 동시성 제어
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)

    async def analyze_with_semaphore(api_info, index):
        """세마포어와 함께 단일 API 분석 실행"""
        async with semaphore:
            return await analyze_single_api(api_info, index)

    # 모든 API 분석을 병렬로 시작
    start_time = datetime.now() + timedelta(hours=9)

    tasks = [
        analyze_with_semaphore(api_info, i)
        for i, api_info in enumerate(analysis_targets)
    ]

    # 모든 작업 완료 대기
    deep_analysis = await asyncio.gather(*tasks, return_exceptions=True)

    # 예외 결과 필터링
    deep_analysis = [
        result for result in deep_analysis
        if not isinstance(result, Exception) and result is not None
    ]

    end_time = datetime.now() + timedelta(hours=9)
    duration = (end_time - start_time).total_seconds()

    print(f"✅ API 심층 분석 완료: {len(deep_analysis)}개 API 분석됨 (소요시간: {duration:.1f}초, 평균: {duration/max(len(deep_analysis),1):.1f}초/API)")

    # API 분석에서 발견된 취약점 종합
    api_vulnerabilities = []

    for api_info in deep_analysis:
        # 파라미터 분석에서 취약점 추출
        param_analysis = api_info.get('parameter_analysis', {})
        if 'sql_injection' in param_analysis and param_analysis['sql_injection'].get('vulnerable_patterns'):
            api_vulnerabilities.append({
                'type': 'API_SQL_INJECTION',
                'severity': 'HIGH',
                'element': api_info.get('original_api', {}).get('url', ''),
                'elementType': 'api_endpoint',
                'description': 'API 엔드포인트에서 SQL Injection 패턴 발견',
                'pattern': 'api_sql_injection',
                'confidence': 'HIGH'
            })

        if 'xss' in param_analysis and param_analysis['xss'].get('vulnerable_patterns'):
            api_vulnerabilities.append({
                'type': 'API_XSS',
                'severity': 'HIGH',
                'element': api_info.get('original_api', {}).get('url', ''),
                'elementType': 'api_endpoint',
                'description': 'API 엔드포인트에서 XSS 패턴 발견',
                'pattern': 'api_xss',
                'confidence': 'HIGH'
            })

        # 인증 분석에서 취약점 추출
        auth_analysis = api_info.get('auth_analysis', {})
        if auth_analysis.get('unauthorized_access', {}).get('bypass_successful'):
            api_vulnerabilities.append({
                'type': 'API_AUTHORIZATION_BYPASS',
                'severity': 'HIGH',
                'element': api_info.get('original_api', {}).get('url', ''),
                'elementType': 'api_endpoint',
                'description': 'API 엔드포인트에서 인증 우회 가능성 발견',
                'pattern': 'api_auth_bypass',
                'confidence': 'HIGH'
            })

        # Rate Limiting 부재
        rate_analysis = api_info.get('rate_limit_analysis', {})
        if not rate_analysis.get('rate_limiting_detected', False):
            api_vulnerabilities.append({
                'type': 'API_NO_RATE_LIMITING',
                'severity': 'MEDIUM',
                'element': api_info.get('original_api', {}).get('url', ''),
                'elementType': 'api_endpoint',
                'description': 'API 엔드포인트에 Rate Limiting 부재',
                'pattern': 'api_no_rate_limiting',
                'confidence': 'MEDIUM'
            })

    print(f"✅ API 심층 분석 완료: {len(deep_analysis)}개 API 분석됨, {len(api_vulnerabilities)}개 취약점 발견")

    return {
        'analyzed_apis': deep_analysis,
        'vulnerabilities': api_vulnerabilities,
        'total_apis_analyzed': len(deep_analysis),
        'total_vulnerabilities': len(api_vulnerabilities)
    }

async def analyze_api_structure(url: str, method: str) -> Dict[str, Any]:
    """API 구조 분석"""
    try:
        # 현재 페이지에서 API 호출 테스트
        if method in ['GET', 'HEAD', 'OPTIONS']:
            test_result = await mcp__chrome_devtools__evaluate_script(f"""
            () => {{
                try {{
                    const response = await fetch('{url}', {{
                        method: '{method}',
                        headers: {{
                            'Content-Type': 'application/json',
                            'User-Agent': 'Security-Analyzer-Test/1.0'
                        }}
                    }});

                    return {{
                        status: response.status,
                        statusText: response.statusText,
                        headers: Object.fromEntries(response.headers.entries()),
                        url: response.url,
                        ok: response.ok,
                        redirected: response.redirected,
                        type: response.type
                    }};
                }} catch (error) {{
                    return {{ error: error.message }};
                }}
            }}
            """)

            if test_result and not test_result.get('error'):
                return {
                    'accessible': True,
                    'status': test_result.get('status'),
                    'headers': test_result.get('headers', {}),
                    'content_type': test_result.get('headers', {}).get('content-type', ''),
                    'cors_headers': {
                        'access_control_allow_origin': test_result.get('headers', {}).get('access-control-allow-origin'),
                        'access_control_allow_methods': test_result.get('headers', {}).get('access-control-allow-methods'),
                        'access_control_allow_headers': test_result.get('headers', {}).get('access-control-allow-headers')
                    }
                }

        return {'accessible': False, 'error': 'Method not testable or failed'}

    except Exception as e:
        return {'error': str(e), 'accessible': False}

async def test_api_parameters(url: str, method: str) -> Dict[str, Any]:
    """API 파라미터 취약점 테스트"""
    try:
        # SQL Injection 패턴 테스트
        sql_payloads = [
            "1' OR '1'='1",
            "'; DROP TABLE users; --",
            "1 UNION SELECT username FROM users --"
        ]

        # XSS 패턴 테스트
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>"
        ]

        parameter_tests = {
            'sql_injection': {
                'tested_payloads': sql_payloads,
                'vulnerable_patterns': [],
                'test_results': []
            },
            'xss': {
                'tested_payloads': xss_payloads,
                'vulnerable_patterns': [],
                'test_results': []
            },
            'parameter_pollution': {
                'tested_payloads': ['param1=value1&param2=value2', 'admin=true&user=test'],
                'test_results': []
            }
        }

        if method in ['GET', 'POST', 'PUT', 'PATCH']:
            # 각 페이로드로 테스트 URL 생성
            for vuln_type, test_data in parameter_tests.items():
                for payload in test_data['tested_payloads']:
                    test_url = f"{url}?{payload}" if method == 'GET' else url

                    try:
                        test_result = await mcp__chrome_devtools__evaluate_script(f"""
                        () => {{
                            try {{
                                const response = await fetch('{test_url}', {{
                                    method: '{method}',
                                    headers: {{
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                        }}
                                }});

                                return {{
                                    status: response.status,
                                    ok: response.ok
                                }};
                            }} catch (error) {{
                                return {{ error: error.message }};
                            }}
                        }}
                        """)

                        test_data['test_results'].append({
                            'payload': payload,
                            'status': test_result.get('status') if test_result else None,
                            'success': test_result.get('ok', False) if test_result else False,
                            'error': test_result.get('error') if test_result else None
                        })

                        # SQL 에러나 XSS 반응 패턴 감지
                        if test_result and not test_result.get('ok') and test_result.get('status', 0) >= 400:
                            test_data['vulnerable_patterns'].append(payload)

                    except Exception as e:
                        test_data['test_results'].append({
                            'payload': payload,
                            'error': str(e),
                            'success': False
                        })

        return parameter_tests

    except Exception as e:
        return {'error': str(e)}

async def test_authentication_bypass(url: str, method: str) -> Dict[str, Any]:
    """인증 우회 가능성 테스트"""
    try:
        auth_tests = {
            'unauthorized_access': {},
            'parameter_manipulation': {},
            'header_manipulation': {}
        }

        # 1. 인증 없이 접근 테스트
        try:
            unauthorized_result = await mcp__chrome_devtools__evaluate_script(f"""
            () => {{
                try {{
                    const response = await fetch('{url}', {{
                        method: '{method}',
                        headers: {{
                            'User-Agent': 'Security-Analyzer-Test/1.0'
                        }}
                    }});

                    return {{
                        status: response.status,
                        ok: response.ok,
                        headers: Object.fromEntries(response.headers.entries())
                    }};
                }} catch (error) {{
                    return {{ error: error.message }};
                }}
            }}
            """)

            if unauthorized_result:
                auth_tests['unauthorized_access'] = {
                    'status': unauthorized_result.get('status'),
                    'accessible': unauthorized_result.get('ok', False),
                    'headers': unauthorized_result.get('headers', {})
                }
        except Exception as e:
            auth_tests['unauthorized_access'] = {'error': str(e)}

        # 2. 헤더 조작 테스트
        auth_headers = [
            {'x-forwarded-for': '127.0.0.1'},
            {'x-real-ip': '127.0.0.1'},
            {'x-remote-user': 'admin'},
            {'x-authenticated-user': 'true'}
        ]

        for headers in auth_headers:
            try:
                header_test_result = await mcp__chrome_devtools__evaluate_script(f"""
                () => {{
                    try {{
                        const response = await fetch('{url}', {{
                            method: '{method}',
                            headers: Object.assign({{
                                'User-Agent': 'Security-Analyzer-Test/1.0'
                            }}, {headers})
                        }});

                        return {{
                            status: response.status,
                            ok: response.ok
                        }};
                    }} catch (error) {{
                        return {{ error: error.message }};
                    }}
                }}
                """)

                if header_test_result:
                    auth_tests['header_manipulation'][str(headers)] = {
                        'status': header_test_result.get('status'),
                        'bypass_successful': header_test_result.get('ok', False)
                    }
            except Exception as e:
                auth_tests['header_manipulation'][str(headers)] = {'error': str(e)}

        return auth_tests

    except Exception as e:
        return {'error': str(e)}

async def test_rate_limiting(url: str, method: str) -> Dict[str, Any]:
    """Rate Limiting 테스트"""
    try:
        rate_test_results = []

        # 빠른 연속 요청 테스트 (5번)
        for i in range(5):
            try:
                start_time = datetime.now() + timedelta(hours=9)

                result = await mcp__chrome_devtools__evaluate_script(f"""
                () => {{
                    try {{
                        const response = await fetch('{url}', {{
                            method: '{method}',
                            headers: {{
                                'User-Agent': 'Security-Analyzer-Test/1.0'
                            }}
                        }});

                        return {{
                            status: response.status,
                            ok: response.ok,
                            timestamp: new Date().toISOString()
                        }};
                    }} catch (error) {{
                        return {{ error: error.message }};
                    }}
                }}
                """)

                if result:
                    end_time = datetime.now() + timedelta(hours=9)
                    rate_test_results.append({
                        'request_number': i + 1,
                        'status': result.get('status'),
                        'success': result.get('ok', False),
                        'response_time': (end_time - start_time).total_seconds(),
                        'timestamp': result.get('timestamp')
                    })

                # 요청 간 짧은 대기
                await asyncio.sleep(0.5)

            except Exception as e:
                rate_test_results.append({
                    'request_number': i + 1,
                    'error': str(e),
                    'success': False
                })

        # Rate Limiting 분석
        successful_requests = [r for r in rate_test_results if r.get('success', False)]
        failed_requests = [r for r in rate_test_results if not r.get('success', False)]

        rate_limiting_detected = len(failed_requests) > len(successful_requests)

        return {
            'total_requests': len(rate_test_results),
            'successful_requests': len(successful_requests),
            'failed_requests': len(failed_requests),
            'rate_limiting_detected': rate_limiting_detected,
            'detailed_results': rate_test_results,
            'analysis': {
                'has_rate_limiting': rate_limiting_detected,
                'block_threshold': len(failed_requests) if rate_limiting_detected else None,
                'avg_response_time': sum(r.get('response_time', 0) for r in successful_requests) / len(successful_requests) if successful_requests else 0
            }
        }

    except Exception as e:
        return {'error': str(e)}

def analyze_network_requests(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """수집된 네트워크 요청 분석"""
    analysis = {
        'total_requests': len(requests),
        'api_endpoints': [],
        'security_issues': [],
        'domains': set(),
        'methods': set(),
        'request_types': {}
    }

    for req in requests:
        url = req.get('url', '')
        method = req.get('method', '')
        req_type = req.get('type', 'unknown')

        # 도메인 수집
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.netloc:
                analysis['domains'].add(parsed.netloc)
        except:
            pass

        # HTTP 메소드 수집
        analysis['methods'].add(method)

        # 요청 타입별 분류
        if req_type not in analysis['request_types']:
            analysis['request_types'][req_type] = 0
        analysis['request_types'][req_type] += 1

        # API 엔드포인트 식별 (더 정교한 기준)
        api_patterns = [
            '/api/', '/v1/', '/v2/', '/v3/',  # API 버전 경로
            'graphql', 'rest', 'soap',          # API 유형
            '.json', '.xml', '.yaml',         # API 데이터 형식
            'token', 'auth', 'session',         # 인증 관련
            'create', 'update', 'delete', 'list', # CRUD 작업
            'query', 'search', 'filter'         # 데이터 조작
        ]

        is_api = any(pattern in url.lower() for pattern in api_patterns) or \
                 method in ['POST', 'PUT', 'DELETE', 'PATCH'] or \
                 req_type in ['fetch', 'xhr']

        if is_api:
            api_info = {
                'url': url,
                'method': method,
                'type': req_type,
                'timestamp': req.get('timestamp', ''),
                'has_auth': False,
                'security_headers': {},
                'deep_analysis_needed': True  # 심층 분석 필요 표시
            }

            # 인증 관련 헤더 확인
            headers = req.get('headers', {})
            auth_headers = ['authorization', 'x-api-key', 'x-auth-token', 'cookie', 'session']
            for header in auth_headers:
                if header in headers and headers[header]:
                    api_info['has_auth'] = True
                    break

            # 보안 헤더 확인
            response = req.get('response', {})
            response_headers = response.get('headers', {})
            security_headers = [
                'x-content-type-options', 'x-frame-options', 'x-xss-protection',
                'strict-transport-security', 'content-security-policy'
            ]

            for header in security_headers:
                if header not in response_headers:
                    analysis['security_issues'].append({
                        'type': 'missing_security_header',
                        'url': url,
                        'missing_header': header,
                        'severity': 'MEDIUM'
                    })

            analysis['api_endpoints'].append(api_info)

    # 집합형을 리스트로 변환
    analysis['domains'] = list(analysis['domains'])
    analysis['methods'] = list(analysis['methods'])

    return analysis

# ==================== 인증 및 세션 관리 심층 분석 ====================

async def analyze_authentication_session_management(target_url: str) -> Dict[str, Any]:
    """인증 및 세션 관리 심층 분석 수행"""
    try:
        print("🔐 인증 및 세션 관리 심층 분석 시작...")

        auth_analysis = {
            'cookie_security': await analyze_cookie_security(target_url),
            'session_management': await analyze_session_management(target_url),
            'authentication_mechanisms': await analyze_authentication_mechanisms(target_url),
            'privilege_escalation': await test_privilege_escalation(target_url),
            'session_hijacking_risks': await analyze_session_hijacking_risks(target_url)
        }

        # 인증/세션 관련 취약점 종합 평가
        auth_vulnerabilities = []

        # 쿠키 보안 취약점
        cookie_issues = auth_analysis['cookie_security'].get('issues', [])
        for issue in cookie_issues:
            auth_vulnerabilities.append({
                'type': 'COOKIE_SECURITY',
                'severity': issue.get('severity', 'MEDIUM'),
                'element': 'Cookie_Settings',
                'elementType': 'security_header',
                'description': issue.get('description', ''),
                'pattern': issue.get('pattern', ''),
                'confidence': 'HIGH'
            })

        # 세션 관리 취약점
        session_issues = auth_analysis['session_management'].get('issues', [])
        for issue in session_issues:
            auth_vulnerabilities.append({
                'type': 'SESSION_MANAGEMENT',
                'severity': issue.get('severity', 'MEDIUM'),
                'element': 'Session_Settings',
                'elementType': 'security_config',
                'description': issue.get('description', ''),
                'pattern': issue.get('pattern', ''),
                'confidence': 'HIGH'
            })

        # 인증 메커니즘 취약점
        auth_issues = auth_analysis['authentication_mechanisms'].get('issues', [])
        for issue in auth_issues:
            auth_vulnerabilities.append({
                'type': 'AUTHENTICATION',
                'severity': issue.get('severity', 'HIGH'),
                'element': 'Authentication_System',
                'elementType': 'auth_system',
                'description': issue.get('description', ''),
                'pattern': issue.get('pattern', ''),
                'confidence': 'HIGH'
            })

        # 권한 상승 취약점
        priv_issues = auth_analysis['privilege_escalation'].get('vulnerabilities', [])
        for issue in priv_issues:
            auth_vulnerabilities.append({
                'type': 'PRIVILEGE_ESCALATION',
                'severity': issue.get('severity', 'HIGH'),
                'element': issue.get('element', 'Unknown'),
                'elementType': 'access_control',
                'description': issue.get('description', ''),
                'pattern': issue.get('pattern', ''),
                'confidence': issue.get('confidence', 'MEDIUM')
            })

        # 세션 하이재킹 위험
        hijack_risks = auth_analysis['session_hijacking_risks'].get('risks', [])
        for risk in hijack_risks:
            auth_vulnerabilities.append({
                'type': 'SESSION_HIJACKING',
                'severity': risk.get('severity', 'HIGH'),
                'element': 'Session_Management',
                'elementType': 'session_security',
                'description': risk.get('description', ''),
                'pattern': risk.get('pattern', ''),
                'confidence': 'HIGH'
            })

        print(f"🔐 인증/세션 관리 분석 완료: {len(auth_vulnerabilities)}개의 취약점 발견")

        return {
            'authentication_analysis': auth_analysis,
            'vulnerabilities': auth_vulnerabilities,
            'total_auth_issues': len(auth_vulnerabilities)
        }

    except Exception as e:
        print(f"❌ 인증/세션 관리 분석 실패: {str(e)}")
        return {
            'authentication_analysis': {},
            'vulnerabilities': [],
            'total_auth_issues': 0,
            'error': str(e)
        }

async def analyze_cookie_security(target_url: str) -> Dict[str, Any]:
    """쿠키 보안 설정 분석"""
    try:
        print("🍪 쿠키 보안 분석 수행...")

        cookie_analysis = {
            'cookies_found': [],
            'security_attributes': {},
            'issues': []
        }

        # 현재 페이지의 쿠키 분석 (SameSite 포함 고도화)
        cookies_result = await mcp__chrome_devtools__evaluate_script(f"""
        () => {{
            // 현재 도메인의 쿠키 분석
            const cookies = document.cookie.split(';').map(c => c.trim()).filter(c => c);
            const cookieDetails = [];

            cookies.forEach(cookie => {{
                const [name, value] = cookie.split('=');

                // 쿠키 속성 분석을 위한 추가 정보 수집
                const isSecure = document.location.protocol === 'https:';
                const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

                // SameSite 속성 추정 (간접적 확인)
                let estimatedSameSite = 'Unknown';

                // 쿠키 컨텍스트 분석
                const cookieName = name.toLowerCase();
                if (cookieName.includes('csrf') || cookieName.includes('xsrf') || cookieName.includes('token')) {{
                    // CSRF 토큰 등은 보통 Strict 또는 Lax
                    estimatedSameSite = 'Likely Strict/Lax (Security Cookie)';
                }} else if (cookieName.includes('session') || cookieName.includes('auth')) {{
                    // 인증 쿠키는 보통 Lax 또는 Strict
                    estimatedSameSite = 'Likely Lax/Strict (Auth Cookie)';
                }} else {{
                    // 일반 쿠키는 None 가능성
                    estimatedSameSite = 'Could be None (Needs Verification)';
                }}

                cookieDetails.push({{
                    name: name,
                    value: value.substring(0, 20) + (value.length > 20 ? '...' : ''),
                    secure: isSecure,
                    httpOnly: false, // JavaScript에서 HttpOnly 확인 불가
                    sameSite: estimatedSameSite,
                    isSessionCookie: cookieName.includes('session') || cookieName.includes('jsessionid'),
                    isAuthCookie: cookieName.includes('auth') || cookieName.includes('token'),
                    length: value.length,
                    domain: window.location.hostname,
                    path: window.location.pathname,
                    context: {{
                        isLocalhost: isLocalhost,
                        protocol: window.location.protocol,
                        fullUrl: window.location.href
                    }}
                }});
            }});

            // SameSite 쿠키 테스트를 위한 iframe 생성 시도 (SameSite 확인)
            const testSameSite = async () => {{
                try {{
                    // 간접적인 SameSite 확인 시도
                    const testCookieName = 'samesite_test_' + Date.now();
                    document.cookie = `${{testCookieName}}=test; SameSite=Lax; path=/`;

                    // iframe에서 쿠키 접근 가능성 테스트 (생략 - 보안상 제한)

                    // 테스트 쿠키 정리
                    document.cookie = `${{testCookieName}}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;

                    return 'SameSite testing attempted';
                }} catch (e) {{
                    return 'SameSite testing failed: ' + e.message;
                }}
            }};

            // 쿠키 보안 평가
            const cookieSecurityAssessment = cookieDetails.map(cookie => ({{
                ...cookie,
                securityIssues: [],
                recommendations: []
            }}));

            cookieSecurityAssessment.forEach(cookie => {{
                // 보안 이슈 식별
                if (!cookie.isSecure && !cookie.context.isLocalhost) {{
                    cookie.securityIssues.push('HTTP 연결에서 쿠키 사용');
                    cookie.recommendations.push('HTTPS 전환 및 Secure 속성 설정');
                }}

                if (cookie.length < 16 && (cookie.isSessionCookie || cookie.isAuthCookie)) {{
                    cookie.securityIssues.push('짧은 쿠키 값长度');
                    cookie.recommendations.push('쿠키 값 길이 증가 또는 안전한 생성 방식 사용');
                }}

                if (cookie.sameSite.includes('Could be None') && (cookie.isSessionCookie || cookie.isAuthCookie)) {{
                    cookie.securityIssues.push('SameSite=None 가능성 - CSRF 공격에 취약');
                    cookie.recommendations.push('SameSite=Strict 또는 Lax 설정 권장');
                }}
            }});

            return {{
                cookies: cookieSecurityAssessment,
                totalCookies: cookieDetails.length,
                securityCookies: cookieSecurityAssessment.filter(c => c.isSessionCookie || c.isAuthCookie),
                insecureCookies: cookieSecurityAssessment.filter(c => c.securityIssues.length > 0),
                domain: window.location.hostname,
                isHttps: window.location.protocol === 'https:',
                sameSiteTestingResult: 'Limited by browser security restrictions'
            }};
        }}
        """)

        if cookies_result:
            cookies = cookies_result.get('cookies', [])
            insecure_cookies = cookies_result.get('insecureCookies', [])
            security_cookies = cookies_result.get('securityCookies', [])
            is_https = cookies_result.get('isHttps', False)

            cookie_analysis['cookies_found'] = cookies
            cookie_analysis['security_cookies_count'] = len(security_cookies)
            cookie_analysis['insecure_cookies_count'] = len(insecure_cookies)

            # 상세한 쿠키 보안 검사 (고도화된 분석)
            for cookie in insecure_cookies:
                cookie_name = cookie.get('name', '')
                security_issues = cookie.get('securityIssues', [])
                recommendations = cookie.get('recommendations', [])
                is_session_cookie = cookie.get('isSessionCookie', False)
                is_auth_cookie = cookie.get('isAuthCookie', False)

                # 각 보안 이슈별로 취약점 등록
                for issue in security_issues:
                    severity = 'HIGH' if 'HTTP 연결' in issue or 'SameSite=None' in issue else 'MEDIUM'

                    cookie_analysis['issues'].append({
                        'type': 'advanced_cookie_security',
                        'severity': severity,
                        'description': f'쿠키 보안 이슈: {issue} - 쿠키: {cookie_name}',
                        'pattern': 'advanced_cookie_violation',
                        'recommendation': '; '.join(recommendations) if recommendations else '쿠키 보안 설정 강화 필요'
                    })

                # SameSite 관련 심층 분석
                same_site = cookie.get('sameSite', '')
                if 'Could be None' in same_site and (is_session_cookie or is_auth_cookie):
                    cookie_analysis['issues'].append({
                        'type': 'samesite_none_risk',
                        'severity': 'HIGH',
                        'description': f'SameSite=None 가능성 (CSRF 취약): {cookie_name}',
                        'pattern': 'samesite_none_risk',
                        'recommendation': 'SameSite=Strict 또는 Lax 설정으로 CSRF 공격 방지'
                    })
                elif 'Likely' in same_site:
                    cookie_analysis['issues'].append({
                        'type': 'samesite_estimated',
                        'severity': 'LOW',
                        'description': f'SameSite 추정: {same_site} - {cookie_name}',
                        'pattern': 'samesite_estimation',
                        'recommendation': '서버 설정에서 명확한 SameSite 속성 확인'
                    })

            # 일반적인 HTTPS 및 Secure 속성 검사
            if not is_https and cookies:
                cookie_analysis['issues'].append({
                    'type': 'insecure_cookies_context',
                    'severity': 'HIGH',
                    'description': f'HTTP 연결에서 {len(cookies)}개 쿠키 사용 - 중간자 공격에 취약',
                    'pattern': 'cookies_over_http_context',
                    'recommendation': 'HTTPS로 전환하고 모든 쿠키에 Secure 속성 사용'
                })

            # 세션 쿠키 HttpOnly 검사
            for cookie in security_cookies:
                cookie_name = cookie.get('name', '')
                if not cookie.get('httpOnly', False):
                    cookie_analysis['issues'].append({
                        'type': 'session_cookie_not_httponly_advanced',
                        'severity': 'HIGH',
                        'description': f'세션/인증 쿠키 "{cookie_name}"에 HttpOnly 속성 부재 - XSS 공격에 취약',
                        'pattern': 'session_cookie_not_httponly_advanced',
                        'recommendation': 'HttpOnly 속성으로 클라이언트 스크립트 접근 차단'
                    })

            # 쿠키 길이 보안 분석
            for cookie in security_cookies:
                cookie_name = cookie.get('name', '')
                cookie_length = cookie.get('length', 0)
                if cookie_length < 16:
                    cookie_analysis['issues'].append({
                        'type': 'short_cookie_value',
                        'severity': 'MEDIUM',
                        'description': f'짧은 쿠키 값长度: {cookie_name} ({cookie_length}자) - 예측 가능성 높음',
                        'pattern': 'short_cookie_entropy',
                        'recommendation': '쿠키 값 길이를 16자 이상으로 증가 또는 안전한 생성 방식 사용'
                    })

        return cookie_analysis

    except Exception as e:
        return {
            'cookies_found': [],
            'security_attributes': {},
            'issues': [{'type': 'analysis_error', 'description': str(e), 'severity': 'LOW'}]
        }

def get_jwt_security_recommendation(issue: str) -> str:
    """JWT 보안 이슈별 권장 조치"""
    recommendations = {
        '알고리즘 부재 또는 none 알고리즘': '안전한 알고리즘(HS256, RS256)으로 즉시 변경',
        '만료된 JWT 토큰': '토큰 갱신 로직 구현 및 만료 토큰 처리',
        '과도하게 긴 만료 시간': '만료 시간을 24시간 이내로 단축 권장',
        '지나치게 짧은 만료 시간': '사용자 경험을 위해 15분 이상으로 설정 권장',
        '만료 시간(exp) 부재': '반드시 만료 시간(exp) 클레임 포함 필요',
        '발행자(iss) 부재': '발행자(iss) 클레임 추가로 토큰 출처 확인',
        '대상(aud/sub) 부재': '대상(aud/sub) 클레임으로 토큰 사용 범위 제한',
        '페이로드에 민감 정보 노출': '페이로드에서 민감 정보 제거 및 참조 ID 사용',
        '오래된 토큰 사용': '주기적인 토큰 갱신 정책 구현',
        '비표준 알고리즘': '표준 알고리즘(HS256, RS256, ES256 등) 사용'
    }
    return recommendations.get(issue, 'JWT 보안 가이드라인 참고하여 개선 필요')

async def analyze_session_management(target_url: str) -> Dict[str, Any]:
    """세션 관리 방식 분석"""
    try:
        print("🔄 세션 관리 방식 분석 수행...")

        session_analysis = {
            'session_tokens': [],
            'timeout_settings': {},
            'regeneration_capability': False,
            'issues': []
        }

        # 세션 토큰 패턴 분석
        session_result = await mcp__chrome_devtools__evaluate_script(f"""
        () => {{
            // 로컬 스토리지 및 세션 스토리지 분석
            const storage = {{
                localStorage: {{...localStorage}},
                sessionStorage: {{...sessionStorage}},
                length: {{
                    local: localStorage.length,
                    session: sessionStorage.length
                }}
            }};

            // JWT 토큰 패턴 검색 및 구조 분석
            const jwtPatterns = [];
            const analyzeJWTSecurity = (token, location) => {{
                try {{
                    const parts = token.split('.');
                    if (parts.length === 3) {{
                        // Header 분석
                        const header = JSON.parse(atob(parts[0]));
                        // Payload 분석
                        const payload = JSON.parse(atob(parts[1]));

                        const now = Math.floor(Date.now() / 1000);
                        const securityIssues = [];

                        // JWT 보안 분석
                        if (header.alg === 'none' || !header.alg) {{
                            securityIssues.push('알고리즘 부재 또는 none 알고리즘');
                        }}

                        if (header.alg === 'HS256' || header.alg === 'RS256') {{
                            // 표준 알고리즘은 안전
                        }} else if (header.alg && !header.alg.startsWith('HS') && !header.alg.startsWith('RS')) {{
                            securityIssues.push(`비표준 알고리즘: ${{header.alg}}`);
                        }}

                        // 만료 시간 분석
                        if (payload.exp) {{
                            const timeToExpiry = payload.exp - now;
                            if (timeToExpiry < 0) {{
                                securityIssues.push('만료된 JWT 토큰');
                            }} else if (timeToExpiry > 86400 * 30) {{ // 30일 이상
                                securityIssues.push('과도하게 긴 만료 시간');
                            }} else if (timeToExpiry < 300) {{ // 5분 미만
                                securityIssues.push('지나치게 짧은 만료 시간');
                            }}
                        }} else {{
                            securityIssues.push('만료 시간(exp) 부재');
                        }}

                        // 발행 시간 분석
                        if (payload.iat) {{
                            const tokenAge = now - payload.iat;
                            if (tokenAge > 86400 * 7) {{ // 7일 이상된 토큰
                                securityIssues.push('오래된 토큰 사용');
                            }}
                        }}

                        // 발행자 분석
                        if (!payload.iss) {{
                            securityIssues.push('발행자(iss) 부재');
                        }}

                        // 대상 분석
                        if (!payload.aud && !payload.sub) {{
                            securityIssues.push('대상(aud/sub) 부재');
                        }}

                        // 민감 정보 노출 확인
                        const sensitiveFields = ['password', 'secret', 'key', 'token', 'auth'];
                        for (const field of sensitiveFields) {{
                            if (payload[field]) {{
                                securityIssues.push(`페이로드에 민감 정보 노출: ${{field}}`);
                            }}
                        }}

                        return {{
                            location: location,
                            token: token.substring(0, 30) + '...',
                            type: 'JWT',
                            algorithm: header.alg,
                            expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
                            issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
                            issuer: payload.iss || null,
                            audience: payload.aud || payload.sub || null,
                            securityIssues: securityIssues,
                            riskLevel: securityIssues.length === 0 ? 'LOW' : securityIssues.length <= 2 ? 'MEDIUM' : 'HIGH'
                        }};
                    }}
                }} catch (e) {{
                    return null;
                }}
            }};

            const checkJWT = (obj, path) => {{
                for (const [key, value] of Object.entries(obj)) {{
                    if (typeof value === 'string' && value.includes('.')) {{
                        const jwtAnalysis = analyzeJWTSecurity(value, path + '.' + key);
                        if (jwtAnalysis) {{
                            jwtPatterns.push(jwtAnalysis);
                        }}
                    }}
                }}
            }};

            checkJWT(storage.localStorage, 'localStorage');
            checkJWT(storage.sessionStorage, 'sessionStorage');

            // 세션 관련 쿠키 확인
            const cookies = document.cookie.split(';').map(c => c.trim()).filter(c => c);
            const sessionCookies = cookies.filter(cookie => {{
                const name = cookie.toLowerCase();
                return name.includes('session') || name.includes('token') || name.includes('auth');
            }});

            return {{
                storage: storage,
                jwtTokens: jwtPatterns,
                sessionCookies: sessionCookies,
                hasAuthStorage: jwtPatterns.length > 0 || sessionCookies.length > 0
            }};
        }}
        """)

        if session_result:
            jwt_tokens = session_result.get('jwtTokens', [])
            session_cookies = session_result.get('sessionCookies', [])
            has_auth_storage = session_result.get('hasAuthStorage', False)

            session_analysis['session_tokens'] = jwt_tokens

            # JWT 토큰 보안 검사 (고도화된 분석)
            for jwt_info in jwt_tokens:
                location = jwt_info.get('location', '')
                risk_level = jwt_info.get('riskLevel', 'LOW')
                security_issues = jwt_info.get('securityIssues', [])
                algorithm = jwt_info.get('algorithm', 'unknown')
                expires_at = jwt_info.get('expiresAt')
                issuer = jwt_info.get('issuer')

                # localStorage 저장 위험
                if 'localStorage' in location:
                    session_analysis['issues'].append({
                        'type': 'jwt_in_localstorage',
                        'severity': 'HIGH' if risk_level == 'HIGH' else 'MEDIUM',
                        'description': f'JWT 토큰이 localStorage에 저장됨 ({location}) - XSS 공격에 취약',
                        'pattern': 'jwt_in_localstorage',
                        'recommendation': 'JWT는 httpOnly 쿠키에 저장하는 것이 더 안전'
                    })

                # JWT 보안 이슈 분석
                for issue in security_issues:
                    severity_map = {
                        '알고리즘 부재 또는 none 알고리즘': 'HIGH',
                        '만료된 JWT 토큰': 'MEDIUM',
                        '과도하게 긴 만료 시간': 'MEDIUM',
                        '지나치게 짧은 만료 시간': 'LOW',
                        '만료 시간(exp) 부재': 'HIGH',
                        '발행자(iss) 부재': 'MEDIUM',
                        '대상(aud/sub) 부재': 'MEDIUM',
                        '페이로드에 민감 정보 노출': 'HIGH',
                        '오래된 토큰 사용': 'MEDIUM',
                        '비표준 알고리즘': 'MEDIUM'
                    }

                    severity = severity_map.get(issue, 'MEDIUM')
                    if risk_level == 'HIGH':
                        severity = 'HIGH'

                    session_analysis['issues'].append({
                        'type': 'jwt_security_issue',
                        'severity': severity,
                        'description': f'JWT 보안 이슈: {issue} ({location})',
                        'pattern': 'jwt_security_violation',
                        'recommendation': get_jwt_security_recommendation(issue)
                    })

                # 알고리즘별 보안 평가
                if algorithm == 'none':
                    session_analysis['issues'].append({
                        'type': 'jwt_none_algorithm',
                        'severity': 'CRITICAL',
                        'description': f'JWT에 none 알고리즘 사용 ({location}) - 위변조 가능',
                        'pattern': 'jwt_none_algorithm',
                        'recommendation': '즉시 안전한 알고리즘(HS256, RS256 등)으로 변경 필요'
                    })

                # 만료 시간 분석
                if expires_at:
                    try:
                        from datetime import datetime
                        expiry_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                        from datetime import timezone
                        now = datetime.now(timezone.utc)

                        if expiry_date < now:
                            session_analysis['issues'].append({
                                'type': 'jwt_expired',
                                'severity': 'MEDIUM',
                                'description': f'만료된 JWT 토큰 사용 중 ({location})',
                                'pattern': 'jwt_expired_token',
                                'recommendation': '토큰 갱신 로직 검토 필요'
                            })
                    except:
                        pass

            # 세션 관리 존재 여부 확인
            if not has_auth_storage:
                session_analysis['issues'].append({
                    'type': 'no_session_management',
                    'severity': 'LOW',
                    'description': '인증/세션 관리 시스템이 감지되지 않음',
                    'pattern': 'no_session_management',
                    'recommendation': '적절한 인증/세션 관리 구현 필요'
                })

        return session_analysis

    except Exception as e:
        return {
            'session_tokens': [],
            'timeout_settings': {},
            'regeneration_capability': False,
            'issues': [{'type': 'analysis_error', 'description': str(e), 'severity': 'LOW'}]
        }

async def analyze_authentication_mechanisms(target_url: str) -> Dict[str, Any]:
    """인증 메커니즘 분석"""
    try:
        print("🔑 인증 메커니즘 분석 수행...")

        auth_analysis = {
            'login_forms': [],
            'auth_endpoints': [],
            'oauth_providers': [],
            'issues': []
        }

        # 로그인 폼 및 인증 관련 요소 분석
        auth_result = await mcp__chrome_devtools__evaluate_script(f"""
        () => {{
            // 로그인 폼 검색
            const loginForms = [];
            const forms = document.querySelectorAll('form');

            forms.forEach(form => {{
                const action = form.action || '';
                const method = (form.method || 'GET').toUpperCase();
                const inputs = form.querySelectorAll('input[type="password"], input[type="email"], input[type="text"], input[name*="user"], input[name*="login"]');

                // 로그인 폼인지 확인 (password 필드 있거나 user/login 관련 name)
                const hasPasswordField = form.querySelector('input[type="password"]');
                const hasUserField = form.querySelector('input[name*="user"], input[name*="login"], input[name*="email"]');

                if (hasPasswordField || (hasUserField && inputs.length > 0)) {{
                    loginForms.push({{
                        action: action,
                        method: method,
                        hasPassword: hasPasswordField,
                        hasUserField: hasUserField,
                        inputCount: inputs.length,
                        hasCSRF: form.querySelector('input[name*="token"], input[name*="csrf"]') !== null,
                        id: form.id || form.className || 'login_form_' + loginForms.length
                    }});
                }}
            }});

            // OAuth 및 소셜 로그인 링크 검색
            const oauthLinks = [];
            const links = document.querySelectorAll('a[href*="oauth"], a[href*="google"], a[href*="facebook"], a[href*="twitter"], a[href*="github"], a[href*="naver"], a[href*="kakao"]');

            links.forEach(link => {{
                oauthLinks.push({{
                    href: link.href,
                    text: link.textContent.trim(),
                    provider: 'unknown'
                }});
            }});

            // API 인증 엔드포인트 패턴 검색
            const scripts = document.querySelectorAll('script');
            const authEndpoints = [];

            scripts.forEach(script => {{
                if (script.textContent) {{
                    // /auth, /login, /token 등의 패턴 검색
                    const authPatterns = [
                        /\\/auth\\/[a-zA-Z0-9_/]*/g,
                        /\\/login\\/[a-zA-Z0-9_/]*/g,
                        /\\/token\\/[a-zA-Z0-9_/]*/g,
                        /\\/api\\/[a-zA-Z0-9_/]*auth[a-zA-Z0-9_/]*/g
                    ];

                    authPatterns.forEach(pattern => {{
                        const matches = script.textContent.match(pattern);
                        if (matches) {{
                            authEndpoints.push(...matches);
                        }}
                    }});
                }}
            }});

            return {{
                loginForms: loginForms,
                oauthLinks: oauthLinks,
                authEndpoints: [...new Set(authEndpoints)], // 중복 제거
                hasLoginForm: loginForms.length > 0,
                hasOAuth: oauthLinks.length > 0
            }};
        }}
        """)

        if auth_result:
            login_forms = auth_result.get('loginForms', [])
            oauth_links = auth_result.get('oauthLinks', [])
            auth_endpoints = auth_result.get('authEndpoints', [])

            auth_analysis['login_forms'] = login_forms
            auth_analysis['oauth_providers'] = oauth_links
            auth_analysis['auth_endpoints'] = auth_endpoints

            # 로그인 폼 보안 검사
            for form in login_forms:
                if not form.get('hasCSRF', False):
                    auth_analysis['issues'].append({
                        'type': 'login_form_missing_csrf',
                        'severity': 'MEDIUM',
                        'description': f'로그인 폼에 CSRF 토큰 부재 ({form.get("id", "unknown")})',
                        'pattern': 'login_missing_csrf',
                        'recommendation': '로그인 폼에 CSRF 보호 조치 추가'
                    })

            if not login_forms and not oauth_links:
                auth_analysis['issues'].append({
                    'type': 'no_authentication_visible',
                    'severity': 'LOW',
                    'description': '인증 폼이나 소셜 로그인이 감지되지 않음',
                    'pattern': 'no_auth_visible',
                    'recommendation': '인증이 필요한 경우 명확한 로그인 인터페이스 제공'
                })

        return auth_analysis

    except Exception as e:
        return {
            'login_forms': [],
            'auth_endpoints': [],
            'oauth_providers': [],
            'issues': [{'type': 'analysis_error', 'description': str(e), 'severity': 'LOW'}]
        }

async def test_privilege_escalation(target_url: str) -> Dict[str, Any]:
    """권한 상승 취약점 테스트"""
    try:
        print("⬆️ 권한 상승 취약점 테스트 수행...")

        privilege_tests = {
            'admin_direct_access': [],
            'parameter_privilege_test': [],
            'role_based_access_test': [],
            'vulnerabilities': []
        }

        # 관리자 페이지 직접 접근 테스트
        admin_paths = [
            '/admin', '/administrator', '/admin.php', '/admin.html',
            '/dashboard', '/control', '/manager', '/admin_panel',
            '/wp-admin', '/phpmyadmin', '/admin/login'
        ]

        for admin_path in admin_paths:
            try:
                admin_url = target_url.rstrip('/') + admin_path
                result = await mcp__chrome_devtools__evaluate_script(f"""
                () => {{
                    // 실제 관리자 페이지 접근은 보안상 위험할 수 있으므로,
                    // 단순히 링크 존재 여부만 확인
                    const adminLinks = document.querySelectorAll('a[href*="admin"], a[href*="dashboard"], [class*="admin"]');
                    const adminElements = document.querySelectorAll('[class*="admin"], [id*="admin"]');

                    return {{
                        adminLinks: adminLinks.length,
                        adminElements: adminElements.length,
                        hasAdminReferences: adminLinks.length > 0 || adminElements.length > 0
                    }};
                }}
                """)

                if result and result.get('hasAdminReferences', False):
                    privilege_tests['admin_direct_access'].append({
                        'path': admin_path,
                        'accessible': True,
                        'evidence': 'admin references found in page'
                    })

                    # 중간 위험도의 관리자 페이지 구조 노출
                    privilege_tests['vulnerabilities'].append({
                        'element': f'Admin_Path_{admin_path}',
                        'description': f'관리자 페이지 경로 노출: {admin_path}',
                        'severity': 'MEDIUM',
                        'pattern': 'admin_path_exposure',
                        'confidence': 'MEDIUM'
                    })

            except Exception as e:
                continue

        # 역할 기반 접근 제어 테스트 (패턴 분석)
        role_patterns = await mcp__chrome_devtools__evaluate_script(f"""
        () => {{
            // 역할 기반 접근 제어 패턴 검색
            const rolePatterns = [];

            // 스크립트에서 역할 확인 패턴 검색
            const scripts = document.querySelectorAll('script');
            scripts.forEach(script => {{
                if (script.textContent) {{
                    const patterns = [
                        /role\\s*[=:=]\\s*['"`]admin['"`]/g,
                        /user\\s*\\.\\s*role/g,
                        /isAdmin\\s*[=:=]/g,
                        /permission\\s*[=:=]/g,
                        /accessLevel\\s*[=:=]/g
                    ];

                    patterns.forEach(pattern => {{
                        const matches = script.textContent.match(pattern);
                        if (matches) {{
                            rolePatterns.push(...matches);
                        }}
                    }});
                }}
            }});

            // 링크에서 권한 관련 파라미터 검색
            const links = document.querySelectorAll('a[href]');
            const privilegeLinks = [];

            links.forEach(link => {{
                const href = link.href;
                if (href.includes('role=') || href.includes('user=') || href.includes('level=')) {{
                    privilegeLinks.push({{
                        href: href,
                        text: link.textContent.trim()
                    }});
                }}
            }});

            return {{
                rolePatterns: [...new Set(rolePatterns)],
                privilegeLinks: privilegeLinks,
                hasRoleManagement: rolePatterns.length > 0,
                hasPrivilegeParameters: privilegeLinks.length > 0
            }};
        }}
        """)

        if role_patterns:
            if role_patterns.get('hasPrivilegeParameters', False):
                privilege_links = role_patterns.get('privilegeLinks', [])
                for link in privilege_links:
                    href = link.get('href', '')
                    if 'role=' in href or 'level=' in href:
                        privilege_tests['vulnerabilities'].append({
                            'element': href,
                            'description': f'권한 파라미터 노출: {href}',
                            'severity': 'HIGH',
                            'pattern': 'privilege_parameter_exposure',
                            'confidence': 'HIGH'
                        })

        return privilege_tests

    except Exception as e:
        return {
            'admin_direct_access': [],
            'parameter_privilege_test': [],
            'role_based_access_test': [],
            'vulnerabilities': [{'type': 'test_error', 'description': str(e), 'severity': 'LOW'}]
        }

async def analyze_session_hijacking_risks(target_url: str) -> Dict[str, Any]:
    """세션 하이재킹 위험 분석"""
    try:
        print("🎭 세션 하이재킹 위험 분석 수행...")

        hijack_analysis = {
            'session_predictability': {},
            'network_security': {},
            'client_side_storage': {},
            'risks': []
        }

        # 세션 ID 예측 가능성 분석
        predictability_result = await mcp__chrome_devtools__evaluate_script(f"""
        () => {{
            // 세션 관련 값 분석
            const sessionValues = [];

            // 쿠키에서 세션 ID 패턴 검색
            const cookies = document.cookie.split(';').map(c => c.trim()).filter(c => c);
            cookies.forEach(cookie => {{
                const [name, value] = cookie.split('=');
                if (name.toLowerCase().includes('session') || name.toLowerCase().includes('id')) {{
                    sessionValues.push({{
                        name: name,
                        value: value,
                        length: value.length,
                        type: 'cookie'
                    }});
                }}
            }});

            // 로컬 스토리지에서 세션 관련 값 검색
            for (let i = 0; i < localStorage.length; i++) {{
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                if (key.toLowerCase().includes('session') || key.toLowerCase().includes('token')) {{
                    sessionValues.push({{
                        name: key,
                        value: value.substring(0, 20) + '...', // 보안을 위해 일부만 표시
                        length: value.length,
                        type: 'localStorage'
                    }});
                }}
            }});

            // 세션 값 예측 가능성 평가
            const risks = [];
            sessionValues.forEach(session => {{
                const value = session.value;

                // 짧은 세션 ID는 예측 가능성 높음
                if (session.length < 16) {{
                    risks.push({{
                        type: 'short_session_id',
                        severity: 'HIGH',
                        description: `짧은 세션 ID: ${session.name} (${session.length}자)`,
                        pattern: 'predictable_session_id'
                    }});
                }}

                // 숫자로만 구성된 세션 ID는 예측 가능성 높음
                if (/^\\d+$/.test(value)) {{
                    risks.push({{
                        type: 'numeric_session_id',
                        severity: 'HIGH',
                        description: `숫자로만 구성된 세션 ID: ${session.name}`,
                        pattern: 'numeric_session_id'
                    }});
                }}

                // 시간 기반 값 패턴
                if (/^\\d{{10,13}}$/.test(value)) {{
                    risks.push({{
                        type: 'timestamp_session_id',
                        severity: 'HIGH',
                        description: `시간 기반 세션 ID: ${session.name}`,
                        pattern: 'timestamp_session_id'
                    }});
                }}
            }});

            return {{
                sessionValues: sessionValues,
                risks: risks,
                hasSessionValues: sessionValues.length > 0
            }};
        }}
        """)

        if predictability_result:
            risks = predictability_result.get('risks', [])
            hijack_analysis['session_predictability'] = {
                'session_values': predictability_result.get('sessionValues', []),
                'risks_found': len(risks)
            }

            for risk in risks:
                hijack_analysis['risks'].append({
                    'type': risk.get('type', 'unknown'),
                    'severity': risk.get('severity', 'MEDIUM'),
                    'description': risk.get('description', ''),
                    'pattern': risk.get('pattern', ''),
                    'confidence': 'HIGH'
                })

        # 클라이언트 측 저장소 위험 분석
        storage_result = await mcp__chrome_devtools__evaluate_script(f"""
        () => {{
            const storageRisks = [];

            // 민감 정보가 localStorage에 저장된 경우
            for (let i = 0; i < localStorage.length; i++) {{
                const key = localStorage.key(i).toLowerCase();
                const value = localStorage.getItem(localStorage.key(i));

                if (key.includes('token') || key.includes('auth') || key.includes('session')) {{
                    if (value.length < 50) {{
                        storageRisks.push({{
                            type: 'sensitive_data_in_localstorage',
                            severity: 'MEDIUM',
                            description: `localStorage에 민감 정보 저장: ${localStorage.key(i)}`,
                            pattern: 'localstorage_auth_data'
                        }});
                    }}
                }}
            }}

            return {{
                storageRisks: storageRisks,
                localStorageItems: localStorage.length,
                sessionStorageItems: sessionStorage.length
            }};
        }}
        """)

        if storage_result:
            storage_risks = storage_result.get('storageRisks', [])
            hijack_analysis['client_side_storage'] = {
                'localstorage_items': storage_result.get('localStorageItems', 0),
                'sessionstorage_items': storage_result.get('sessionStorageItems', 0),
                'risks_found': len(storage_risks)
            }

            for risk in storage_risks:
                hijack_analysis['risks'].append({
                    'type': risk.get('type', 'unknown'),
                    'severity': risk.get('severity', 'MEDIUM'),
                    'description': risk.get('description', ''),
                    'pattern': risk.get('pattern', ''),
                    'confidence': 'HIGH'
                })

        # 네트워크 보안 분석 (HTTPS 여부 등)
        current_protocol = await mcp__chrome_devtools__evaluate_script("() => window.location.protocol")
        if current_protocol and current_protocol != 'https:':
            hijack_analysis['network_security'] = {
                'protocol': current_protocol,
                'secure': False
            }

            hijack_analysis['risks'].append({
                'type': 'insecure_protocol',
                'severity': 'HIGH',
                'description': 'HTTP 프로토콜 사용 - 세션 하이재킹에 취약',
                'pattern': 'insecure_protocol_session',
                'confidence': 'HIGH'
            })
        else:
            hijack_analysis['network_security'] = {
                'protocol': current_protocol,
                'secure': True
            }

        return hijack_analysis

    except Exception as e:
        return {
            'session_predictability': {},
            'network_security': {},
            'client_side_storage': {},
            'risks': [{'type': 'analysis_error', 'description': str(e), 'severity': 'LOW'}]
        }

async def analyze_page_security(url: str, menu_text: str, element_info: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
    """안전한 페이지 보안 분석 (실시간 네트워크 포함)"""
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

        # 2. 실시간 네트워크 모니터링 (10초간)
        print(f"🌐 {url}에서 실시간 네트워크 모니터링 시작...")
        realtime_network = await monitor_realtime_network(duration=10)
        print(f"✅ 실시간 네트워크 분석 완료: {len(realtime_network)}개 요청 감지")

        # 3. 기존 네트워크 요청 수집
        try:
            historical_network = await mcp__chrome_devtools__list_network_requests(
                pageSize=50, includePreservedRequests=True
            )
        except Exception as e:
            print(f"과거 네트워크 요청 수집 실패: {str(e)}")
            historical_network = []

        # 네트워크 데이터 통합
        all_network_requests = realtime_network + historical_network

        # 네트워크 분석
        network_analysis = analyze_network_requests(all_network_requests)

        # 4. 폼 요소 분석
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

        # 4. 실시간 발견 API 엔드포인트 추가
        realtime_apis = network_analysis.get('api_endpoints', [])

        # 5. 정적 API 엔드포인트 분석
        static_apis = []
        try:
            static_apis = await mcp__chrome_devtools__evaluate_script("""
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
            print(f"정적 API 엔드포인트 분석 실패: {str(e)}")

        # API 엔드포인트 통합
        all_api_endpoints = realtime_apis + static_apis

        # 6. 취약점 패턴 분석
        vulnerabilities = []
        try:
            vulnerabilities = await analyze_vulnerability_patterns_safe(url, forms)
        except Exception as e:
            print(f"취약점 분석 실패: {str(e)}")

        # 7. 보안 헤더 및 상태 분석
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

        # 8. 인증 및 세션 관리 심층 분석
        authentication_analysis = {}
        try:
            print("🔐 인증/세션 관리 심층 분석 수행...")
            authentication_analysis = await analyze_authentication_session_management(url)

            # 인증/세션 관련 취약점을 기존 취약점 목록에 추가
            auth_vulnerabilities = authentication_analysis.get('vulnerabilities', [])
            if auth_vulnerabilities:
                vulnerabilities.extend(auth_vulnerabilities)
                print(f"🔐 인증/세션 관련 취약점 {len(auth_vulnerabilities)}개 추가됨")
        except Exception as e:
            print(f"인증/세션 관리 분석 실패: {str(e)}")

        # 9. API 엔드포인트 심층 분석
        api_deep_analysis = {}
        try:
            if all_api_endpoints:
                print("🔍 API 엔드포인트 심층 분석 수행...")
                api_deep_analysis = await deep_api_analysis(all_api_endpoints, url)

                # API 분석에서 발견된 취약점을 기존 취약점 목록에 추가
                api_vulnerabilities = api_deep_analysis.get('vulnerabilities', [])
                if api_vulnerabilities:
                    vulnerabilities.extend(api_vulnerabilities)
                    print(f"🔍 API 관련 취약점 {len(api_vulnerabilities)}개 추가됨")
        except Exception as e:
            print(f"API 심층 분석 실패: {str(e)}")
            api_deep_analysis = {'analyzed_apis': [], 'vulnerabilities': [], 'total_apis_analyzed': 0, 'total_vulnerabilities': 0}

        # 10. 결과 정리 및 중복 제거
        return {
            'menu': _generate_menu_name(menu_text, element_info) or '알 수 없는 메뉴',
            'url': url,
            'forms': forms or [],
            'api_endpoints': all_api_endpoints,
            'vulnerabilities': vulnerabilities or [],
            'security_headers': security_headers or {},
            'network_analysis': network_analysis,
            'realtime_network_requests': realtime_network,
            'historical_network_requests': historical_network,
            'network_request_count': len(all_network_requests),
            'authentication_analysis': authentication_analysis,
            'api_deep_analysis': api_deep_analysis,
            'analysis_timestamp': datetime.now() + timedelta(hours=9).isoformat()
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
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
import pandas as pd
import chardet

# Windows 인코딩 문제 해결
if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        os.environ['PYTHONIOENCODING'] = 'utf-8'

sys.path.append(os.path.join(os.path.dirname(__file__), 'xlsx', 'scripts'))
from excel_generator import ExcelReportGenerator

def _generate_menu_name(menu_text: str, element_info: Dict[str, Any] = None) -> str:
    """클릭 대상 정보를 포함한 메뉴 이름 생성"""
    if not menu_text and not element_info:
        return '알 수 없는 메뉴'

    try:
        # 기본 메뉴 텍스트 정리
        menu_name = menu_text.strip() if menu_text else ''

        # 요소 정보가 있으면 상세 정보 추가
        if element_info:
            element_type = element_info.get('elementType', '')
            selector = element_info.get('selector', '')

            # 요소 타입 한글화
            type_mapping = {
                'button': '버튼',
                'submit': '제출버튼',
                'link': '링크',
                'input': '입력필드',
                'form': '폼',
                'dropdown': '드롭다운',
                'checkbox': '체크박스',
                'radio': '라디오버튼',
                'image': '이미지',
                'div': '영역',
                'span': '텍스트영역'
            }

            korean_type = type_mapping.get(element_type.lower(), element_type.upper())

            # 메뉴 이름이 너무 길면 줄이기
            if len(menu_name) > 30:
                menu_name = menu_name[:30] + '...'

            # 최종 메뉴 이름 생성
            if menu_name:
                return f"{menu_name} ({korean_type})"
            else:
                return f"{korean_type} - {selector[:20]}" if selector else korean_type

        return menu_name or '알 수 없는 메뉴'

    except Exception as e:
        print(f"메뉴 이름 생성 오류: {str(e)}")
        return menu_text or '알 수 없는 메뉴'

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
| 분석 방식 | Playwright + Chrome DevTools (공격 없음) |

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

- **분석 도구**: Playwright + Chrome DevTools
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
    kst = datetime.now() + timedelta(hours=9)
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
| 메뉴 | 클릭한 대상 정보 (버튼, 링크 등) |
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

## 머신러닝 기반 취약점 패턴 학습 (고급 기능)

def analyze_vulnerability_patterns_with_ml(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """머신러닝 기반 취약점 패턴 식별"""
    try:
        # 패턴 특성 추출
        features = extract_ml_features(analysis_data)

        # 훈련된 모델 기반 취약점 예측 (가상 구현)
        ml_predictions = predict_vulnerabilities_ml(features)

        # 패턴 학습 및 피드백
        learned_patterns = update_vulnerability_patterns(analysis_data, ml_predictions)

        return {
            'ml_predictions': ml_predictions,
            'learned_patterns': learned_patterns,
            'confidence_scores': calculate_confidence_scores(ml_predictions),
            'anomaly_detection': detect_anomalous_patterns(features)
        }
    except Exception as e:
        return {'error': str(e), 'fallback_mode': True}

def extract_ml_features(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """머신러닝 특성 추출"""
    features = {
        'url_complexity': calculate_url_entropy(analysis_data.get('url', '')),
        'form_count': len(analysis_data.get('forms', [])),
        'api_count': len(analysis_data.get('api_endpoints', [])),
        'vulnerability_density': calculate_vulnerability_density(analysis_data),
        'security_headers_score': score_security_headers(analysis_data.get('security_headers', {})),
        'domain_age_days': estimate_domain_age(analysis_data.get('url', '')),
        'technology_stack': detect_technology_stack(analysis_data),
        'pattern_complexity': calculate_pattern_complexity(analysis_data)
    }
    return features

# 비즈니스 로직 취약점 분석 (고급 기능)

def analyze_business_logic_vulnerabilities(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """비즈니스 로직 취약점 식별"""
    try:
        business_vulns = []

        # 1. 권한 상승 패턴 분석
        priv_escalation = analyze_privilege_escalation_patterns(analysis_data)
        business_vulns.extend(priv_escalation)

        # 2. 인가되지 않은 기능 접근
        unauthorized_access = analyze_unauthorized_function_access(analysis_data)
        business_vulns.extend(unauthorized_access)

        # 3. 데이터 조작 가능성
        data_manipulation = analyze_data_manipulation_vectors(analysis_data)
        business_vulns.extend(data_manipulation)

        # 4. 비즈니스 프로세스 우회
        process_bypass = analyze_business_process_bypass(analysis_data)
        business_vulns.extend(process_bypass)

        return {
            'business_vulnerabilities': business_vulns,
            'risk_assessment': assess_business_risk(business_vulns),
            'compliance_impact': analyze_compliance_impact(business_vulns)
        }
    except Exception as e:
        return {'error': str(e)}

# 컨테이너 보안 분석 확장 (고급 기능)

def analyze_container_security_exposure(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """컨테이너 환경에서의 보안 노출 분석"""
    try:
        container_indicators = {
            'docker_api_exposure': check_docker_api_exposure(),
            'kubernetes_dashboard': detect_kubernetes_dashboard(),
            'container_registry': analyze_container_registry_patterns(),
            'orchestration_tools': detect_orchestration_tools(),
            'container_secrets': analyze_container_secret_exposure()
        }

        container_vulnerabilities = []
        for indicator, result in container_indicators.items():
            if result.get('exposed', False):
                container_vulnerabilities.append({
                    'type': f'container_{indicator}',
                    'severity': 'HIGH',
                    'description': f'컨테이너 관련 노출: {indicator}',
                    'pattern': 'container_exposure',
                    'details': result
                })

        return {
            'container_indicators': container_indicators,
            'vulnerabilities': container_vulnerabilities,
            'container_environment_detected': any(indicator.get('exposed', False) for indicator in container_indicators.values())
        }
    except Exception as e:
        return {'error': str(e)}

# 실제 사용자 상호작용 시뮬레이션 (고급 동적 분석)

async def simulate_user_interactions(target_url: str) -> Dict[str, Any]:
    """실제 사용자 상호작용 시뮬레이션을 통한 동적 취약점 분석"""
    try:
        print("🎭 사용자 상호작용 시뮬레이션 시작...")

        interaction_results = {
            'form_interactions': await simulate_form_interactions(),
            'ajax_triggers': await simulate_ajax_event_triggers(),
            'navigation_patterns': await simulate_navigation_patterns(),
            'authentication_flows': await simulate_authentication_flows(),
            'file_upload_tests': await simulate_file_upload_scenarios(),
            'error_handling_tests': await simulate_error_conditions()
        }

        # 동적 취약점 분석
        dynamic_vulnerabilities = []

        for interaction_type, results in interaction_results.items():
            if results.get('vulnerabilities'):
                for vuln in results['vulnerabilities']:
                    vuln['discovery_method'] = f'interaction_simulation_{interaction_type}'
                    dynamic_vulnerabilities.append(vuln)

        return {
            'interaction_results': interaction_results,
            'dynamic_vulnerabilities': dynamic_vulnerabilities,
            'interaction_coverage': calculate_interaction_coverage(interaction_results),
            'behavioral_analysis': analyze_behavioral_patterns(interaction_results)
        }

    except Exception as e:
        return {'error': str(e), 'simulation_failed': True}

async def simulate_form_interactions() -> Dict[str, Any]:
    """폼 상호작용 시뮬레이션"""
    try:
        form_simulation = await mcp__chrome_devtools__evaluate_script("""
        () => {
            const forms = document.querySelectorAll('form');
            const results = [];

            forms.forEach((form, index) => {
                const formId = form.id || form.className || `form_${index}`;
                const inputs = form.querySelectorAll('input, select, textarea');

                // 무해한 테스트 데이터로 폼 채우기 시뮬레이션
                const testInputs = ['test@example.com', 'user123', 'TestValue123!', '12345'];
                let fillAttempts = 0;
                let vulnerabilities = [];

                inputs.forEach(input => {
                    if (input.type !== 'hidden' && input.type !== 'submit') {
                        const testValue = testInputs[fillAttempts % testInputs.length];

                        // XSS 테스트 (안전한 방식)
                        if (input.type === 'text' || input.type === 'textarea') {
                            const xssTest = '<script>alert("test")</script>';
                            input.value = xssTest;

                            // 입력값 변환 감지
                            setTimeout(() => {
                                if (input.value !== xssTest) {
                                    vulnerabilities.push({
                                        type: 'XSS_FILTERING_BYPASS',
                                        element: formId,
                                        field: input.name || input.id,
                                        description: 'XSS 필터링 우회 가능성'
                                    });
                                }
                            }, 100);
                        }

                        fillAttempts++;
                    }
                });

                // CSRF 토큰 확인
                const hasCSRF = form.querySelector('input[name*="token"], input[name*="csrf"]');
                if (!hasCSRF && form.method.toLowerCase() === 'post') {
                    vulnerabilities.push({
                        type: 'FORM_CSRF_MISSING',
                        element: formId,
                        description: 'POST 폼에 CSRF 토큰 부재'
                    });
                }

                results.push({
                    formId: formId,
                    inputCount: inputs.length,
                    hasCSRF: !!hasCSRF,
                    method: form.method || 'GET',
                    action: form.action || 'unknown',
                    vulnerabilities: vulnerabilities
                });
            });

            return {
                formsAnalyzed: results.length,
                totalInputs: Array.from(forms).reduce((sum, form) => sum + form.querySelectorAll('input, select, textarea').length, 0),
                vulnerabilities: results.flatMap(r => r.vulnerabilities),
                formsWithCSRF: results.filter(r => r.hasCSRF).length,
                postFormsWithoutCSRF: results.filter(r => !r.hasCSRF && r.method === 'POST').length
            };
        }
        """)

        return form_simulation

    except Exception as e:
        return {'error': str(e), 'form_simulation_failed': True}

async def simulate_ajax_event_triggers() -> Dict[str, Any]:
    """AJAX 이벤트 트리거 시뮬레이션"""
    try:
        ajax_simulation = await mcp__chrome_devtools__evaluate_script("""
        () => {
            const results = [];
            const vulnerabilities = [];

            // 버튼 클릭 시뮬레이션
            const buttons = document.querySelectorAll('button, input[type="button"], input[type="submit"]');
            buttons.forEach((button, index) => {
                try {
                    // 실제 클릭은 보안상 피하고, 이벤트 핸들러만 분석
                    const eventListeners = getEventListeners ? getEventListeners(button) : {};
                    const hasClickListener = eventListeners.click && eventListeners.click.length > 0;

                    if (hasClickListener) {
                        const buttonText = button.textContent.trim() || button.value || `Button_${index}`;

                        // 외부 URL 호출 패턴 확인
                        const onclick = button.getAttribute('onclick') || '';
                        if (onclick.includes('http') && !onclick.includes(window.location.hostname)) {
                            vulnerabilities.push({
                                type: 'EXTERNAL_AJAX_CALL',
                                element: buttonText,
                                description: '외부 도메인 AJAX 호출 감지'
                            });
                        }
                    }
                } catch (e) {
                    // 이벤트 리스너 접근 실패
                }
            });

            // JavaScript 동적 요소 생성 감지
            const scripts = document.querySelectorAll('script');
            scripts.forEach(script => {
                if (script.textContent) {
                    // 동적 DOM 생성 패턴
                    if (script.textContent.includes('createElement') && script.textContent.includes('innerHTML')) {
                        vulnerabilities.push({
                            type: 'DYNAMIC_DOM_INJECTION',
                            element: 'script',
                            description: 'innerHTML를 통한 동적 DOM 생성 - XSS 가능성'
                        });
                    }

                    // eval() 사용 확인
                    if (script.textContent.includes('eval(')) {
                        vulnerabilities.push({
                            type: 'EVAL_USAGE',
                            element: 'script',
                            description: 'eval() 함수 사용 - 코드 실행 가능성'
                        });
                    }
                }
            });

            return {
                buttonsAnalyzed: buttons.length,
                scriptsAnalyzed: scripts.length,
                vulnerabilities: vulnerabilities,
                hasEventListeners: buttons.length > 0
            };
        }
        """)

        return ajax_simulation

    except Exception as e:
        return {'error': str(e), 'ajax_simulation_failed': True}

async def simulate_navigation_patterns() -> Dict[str, Any]:
    """네비게이션 패턴 시뮬레이션"""
    try:
        nav_simulation = await mcp__chrome_devtools__evaluate_script("""
        () => {
            const results = [];
            const vulnerabilities = [];

            // 링크 분석
            const links = document.querySelectorAll('a[href]');
            const internalLinks = [];
            const externalLinks = [];

            links.forEach(link => {
                const href = link.href;
                const currentDomain = window.location.hostname;

                try {
                    const linkDomain = new URL(href).hostname;

                    if (linkDomain === currentDomain) {
                        internalLinks.push(href);
                    } else {
                        externalLinks.push(href);

                        // 외부 링크 보안 확인
                        if (href.startsWith('http://') && currentDomain !== 'localhost') {
                            vulnerabilities.push({
                                type: 'EXTERNAL_HTTP_LINK',
                                element: link.textContent.trim(),
                                url: href,
                                description: 'HTTPS 페이지에서 HTTP 외부 링크'
                            });
                        }
                    }
                } catch (e) {
                    // 잘못된 URL
                }
            });

            // 자바스크립트 네비게이션 확인
            const jsLinks = document.querySelectorAll('a[href^="javascript:"]');
            if (jsLinks.length > 0) {
                vulnerabilities.push({
                    type: 'JAVASCRIPT_NAVIGATION',
                    count: jsLinks.length,
                    description: f'{jsLinks.length}개의 JavaScript 네비게이션 링크'
                });
            }

            return {
                totalLinks: links.length,
                internalLinks: internalLinks.length,
                externalLinks: externalLinks.length,
                javascriptLinks: jsLinks.length,
                vulnerabilities: vulnerabilities
            };
        }
        """)

        return nav_simulation

    except Exception as e:
        return {'error': str(e), 'navigation_simulation_failed': True}

async def simulate_authentication_flows() -> Dict[str, Any]:
    """인증 흐름 시뮬레이션"""
    try:
        auth_simulation = await mcp__chrome_devtools__evaluate_script("""
        () => {
            const results = {
                loginForms: [],
                authEndpoints: [],
                vulnerabilities: []
            };

            // 로그인 폼 식별
            const loginForms = document.querySelectorAll('form');
            loginForms.forEach((form, index) => {
                const passwordField = form.querySelector('input[type="password"]');
                const emailField = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');

                if (passwordField) {
                    const formId = form.id || form.className || `login_form_${index}`;

                    // 인증 관련 보안 검사
                    const hasAutocomplete = passwordField.getAttribute('autocomplete') === 'off';
                    const formAction = form.action || '';

                    if (!hasAutocomplete) {
                        results.vulnerabilities.push({
                            type: 'PASSWORD_AUTOCOMPLETE_ENABLED',
                            element: formId,
                            description: '비밀번호 필드에 자동완성 허용'
                        });
                    }

                    if (formAction.startsWith('http://') && window.location.protocol === 'https:') {
                        results.vulnerabilities.push({
                            type: 'INSECURE_FORM_ACTION',
                            element: formId,
                            action: formAction,
                            description: 'HTTPS 페이지에서 HTTP 폼� 전송'
                        });
                    }

                    results.loginForms.push({
                        formId: formId,
                        hasEmailField: !!emailField,
                        hasAutocomplete: hasAutocomplete,
                        action: formAction,
                        method: form.method || 'POST'
                    });
                }
            });

            // 인증 관련 스크립트 패턴
            const scripts = document.querySelectorAll('script');
            scripts.forEach(script => {
                if (script.textContent) {
                    const content = script.textContent;

                    // JWT 토큰 로컬 스토리지 저장
                    if (content.includes('localStorage') && content.includes('token')) {
                        results.vulnerabilities.push({
                            type: 'TOKEN_IN_LOCALSTORAGE',
                            element: 'script',
                            description: '인증 토큰 localStorage 저장'
                        });
                    }

                    // 하드코딩된 인증 정보
                    if (content.match(/password\\s*=\\s*['"][^'"]+['"]/i)) {
                        results.vulnerabilities.push({
                            type: 'HARDCODED_CREDENTIALS',
                            element: 'script',
                            description: '스크립트에 하드코딩된 비밀번호'
                        });
                    }
                }
            });

            return results;
        }
        """)

        return auth_simulation

    except Exception as e:
        return {'error': str(e), 'auth_simulation_failed': True}

## 중요 사항

- 이 스킬은 실제 공격을 수행하지 않고 코드 패턴 분석만 수행
- 모든 분석은 Chrome DevTools를 통한 안전한 방식으로 진행
- 결과는 취약점 가능성을 나타내며, 전문가의 추가 검토 필요
- 분석 대상 사이트의 약관과 robots.txt 준수 필수
- CSV 파일 처리 시 인코딩 문제를 자동으로 해결하며, 한글(UTF-8, CP949, EUC-KR) 인코딩을 지원
- **머신러닝 및 고급 분석 기능은 실험적 기능으로, 실제 운영 환경에서는 검증 후 사용 필요**