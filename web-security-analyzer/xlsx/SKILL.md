---
name: web-security-analyzer:xlsx
description: Comprehensive web security vulnerability analyzer that systematically analyzes entire websites through real browser automation and generates detailed Excel reports with vulnerability findings.
parameters:
  - name: target_url
    type: string
    description: Target website URL to analyze for security vulnerabilities
    required: true
  - name: username
    type: string
    description: Username for authentication (if required)
    required: false
  - name: password
    type: string
    description: Password for authentication (if required)
    required: false
---

# 웹 보안 취약점 분석 스킬

## ✶ Insight ─────────────────────────────
이 스킬은 Playwright 기반의 실제 브라우저 자동화를 통해 웹사이트 전체를 탐색하며 보안 취약점을 분석합니다. 모든 메뉴 클릭, 폼 상호작용, 페이지 탐색을 실제 사용자처럼 수행하며 XSS, SQL 인젝션 등 다양한 보안 위협 패턴을 식별하고 상세한 엑셀 보고서를 생성합니다.
────────────────────────────────────────────────

## 사용 시점

이 스킬은 다음과 같은 상황에서 사용합니다:
- 웹사이트 전체의 보안 상태를 종합적으로 평가할 때
- 모든 메뉴와 기능별 취약점을 체계적으로 분석할 때
- XSS, SQL Injection을 포함한 다양한 취약점 패턴을 식별할 때
- 웹 애플리케이션의 모든 HTTP 요청과 파라미터를 문서화할 때
- 보안 감사를 위한 상세 분석 보고서가 필요할 때

## 분석 절차

### 1. 스킬 설정 및 초기화

```python
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd
import openpyxl
from openpyxl.styles import PatternFill, Font
from openpyxl.utils.dataframe import dataframe_to_rows
import chardet
import subprocess
import sys

# 스킬 설정
ANALYSIS_CONFIG = {
    'max_depth': 3,           # 메뉴 탐색 깊이
    'max_pages': 50,          # 최대 분석 페이지 수
    'timeout': 30,            # 페이지 타임아웃(초)
    'retry_count': 3,         # 실패시 재시도 횟수
    'skip_dynamic': False,    # 동적 콘텐츠 분석 생략 여부
    'headless': True,         # 헤드리스 모드
    'slow_mo': 100           # 동작 지연(ms)
}

# MCP 함수 래퍼
async def playwright_navigate(url: str) -> bool:
    """Playwright로 페이지 탐색"""
    try:
        await mcp__playwright__navigate_page(url=url)
        return True
    except Exception as e:
        print(f"페이지 탐색 실패: {e}")
        return False

async def playwright_evaluate_script(script: str, *args) -> Any:
    """Playwright로 스크립트 실행"""
    try:
        return await mcp__playwright__evaluate_script(function=script, args=args)
    except Exception as e:
        print(f"스크립트 실행 실패: {e}")
        return None

async def playwright_click_element(selector: str) -> bool:
    """요소 클릭"""
    try:
        await mcp__playwright__click(uid=selector)
        return True
    except Exception as e:
        print(f"요소 클릭 실패: {e}")
        return False

async def playwright_screenshot(filename: str) -> bool:
    """스크린샷 저장"""
    try:
        await mcp__playwright__take_screenshot(
            format="png",
            quality=90,
            fullPage=True,
            filePath=filename
        )
        return True
    except Exception as e:
        print(f"스크린샷 실패: {e}")
        return False
```

### 2. 핵심 보안 분석 함수

```python
async def analyze_page_security(url: str, menu_text: str = "Unknown") -> Dict[str, Any]:
    """페이지 보안 분석"""
    print(f"🔍 분석 중: {menu_text} ({url})")

    result = {
        'menu': menu_text,
        'url': url,
        'vulnerabilities_found': [],
        'security_tests': [],
        'analysis_timestamp': datetime.now() + timedelta(hours=9)
    }

    # 페이지 접속 확인
    if not await playwright_navigate(url):
        result['security_tests'].append({
            'test': 'page_access',
            'status': 'failed',
            'message': f'페이지 접속 실패: {url}'
        })
        return result

    result['security_tests'].append({
        'test': 'page_access',
        'status': 'passed',
        'message': '페이지 접속 성공'
    })

    # 보안 취약점 분석 스크립트 실행
    security_script = """
    () => {
        const vulnerabilities = [];
        const security_tests = [];

        // 1. XSS 취약점 검사
        const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea');
        inputs.forEach((input, index) => {
            const inputId = input.id || input.name || `input_${index}`;

            // 입력값 검증 확인
            if (!input.pattern && !input.maxLength) {
                vulnerabilities.push({
                    type: 'XSS',
                    severity: 'MEDIUM',
                    element: inputId,
                    elementType: 'input',
                    description: '입력값 길이 제한 및 패턴 검증 부재',
                    pattern: 'no_input_validation',
                    confidence: 'MEDIUM'
                });
            }
        });

        // 2. CSRF 취약점 검사
        const forms = document.querySelectorAll('form');
        forms.forEach((form, index) => {
            const formId = form.id || form.className || `form_${index}`;
            const method = (form.method || 'GET').toLowerCase();

            if (method === 'post') {
                const csrfSelectors = [
                    'input[name*="token"]',
                    'input[name*="csrf"]',
                    'input[name*="_token"]'
                ];

                let hasToken = false;
                for (const selector of csrfSelectors) {
                    if (form.querySelector(selector)) {
                        hasToken = true;
                        break;
                    }
                }

                if (!hasToken) {
                    vulnerabilities.push({
                        type: 'CSRF',
                        severity: 'MEDIUM',
                        element: formId,
                        elementType: 'form',
                        description: 'CSRF 토큰 부재',
                        pattern: 'missing_csrf_token',
                        confidence: 'HIGH'
                    });
                }
            }
        });

        // 3. 보안 헤더 확인
        security_tests.push({
            test: 'security_headers',
            status: 'info',
            message: '보안 헤더 분석은 서버 응답 필요'
        });

        // 4. 외부 링크 보안 검사
        const links = document.querySelectorAll('a[href]');
        let insecureLinks = 0;

        links.forEach(link => {
            const href = link.getAttribute('href');
            if (href && href.startsWith('http://') && window.location.protocol === 'https:') {
                insecureLinks++;
            }
        });

        if (insecureLinks > 0) {
            vulnerabilities.push({
                type: 'MIXED_CONTENT',
                severity: 'LOW',
                element: f'{insecureLinks}개 링크',
                elementType: 'link',
                description: 'HTTPS 페이지에서 HTTP 링크 존재',
                pattern: 'insecure_external_links',
                confidence: 'HIGH'
            });
        }

        // 5. 인증 관련 보안 검사
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        passwordInputs.forEach((input, index) => {
            const inputId = input.id || input.name || `password_${index}`;

            // 자동완성 속성 확인
            if (input.getAttribute('autocomplete') !== 'off') {
                vulnerabilities.push({
                    type: 'PASSWORD_AUTOCOMPLETE',
                    severity: 'LOW',
                    element: inputId,
                    elementType: 'input',
                    description: '비밀번호 필드 자동완성 허용',
                    pattern: 'password_autocomplete_enabled',
                    confidence: 'MEDIUM'
                });
            }
        });

        return {
            vulnerabilities: vulnerabilities,
            security_tests: security_tests,
            page_info: {
                title: document.title,
                total_forms: forms.length,
                total_inputs: inputs.length,
                total_links: links.length,
                has_password_fields: passwordInputs.length > 0
            }
        };
    }
    """

    try:
        analysis = await playwright_evaluate_script(security_script)
        if analysis:
            result['vulnerabilities_found'] = analysis.get('vulnerabilities', [])
            result['security_tests'].extend(analysis.get('security_tests', []))
            result['page_info'] = analysis.get('page_info', {})

            print(f"   ✅ 취약점 {len(result['vulnerabilities_found'])}개 발견")
            for vuln in result['vulnerabilities_found']:
                print(f"      - {vuln['type']}: {vuln['description']}")
        else:
            result['security_tests'].append({
                'test': 'security_analysis',
                'status': 'failed',
                'message': '보안 분석 스크립트 실행 실패'
            })
    except Exception as e:
        result['security_tests'].append({
            'test': 'security_analysis',
            'status': 'failed',
            'message': f'분석 오류: {str(e)}'
        })

    return result

async def discover_menus_and_analyze(max_pages: int = 50) -> List[Dict[str, Any]]:
    """메뉴 발견 및 보안 분석"""
    print("🔍 웹사이트 메뉴 구조 분석 중...")

    # 현재 페이지의 모든 링크 분석
    discovery_script = """
    () => {
        const links = Array.from(document.querySelectorAll('a[href]'));
        const menuItems = [];
        const seenUrls = new Set();

        links.forEach(link => {
            const href = link.getAttribute('href');
            const text = link.textContent.trim();

            if (href && text && href !== '#' && !href.startsWith('javascript:') && !href.startsWith('mailto:')) {
                // 절대 URL로 변환
                let fullUrl = href;
                if (href.startsWith('/')) {
                    fullUrl = window.location.origin + href;
                } else if (!href.startsWith('http')) {
                    fullUrl = window.location.href + href;
                }

                if (!seenUrls.has(fullUrl) && fullUrl.startsWith(window.location.origin)) {
                    seenUrls.add(fullUrl);
                    menuItems.push({
                        url: fullUrl,
                        text: text,
                        element: link.tagName.toLowerCase(),
                        selector: link.id || `a[href="${href}"]`
                    });
                }
            }
        });

        return menuItems.slice(0, 50); // 최대 50개까지
    }
    """

    try:
        menu_items = await playwright_evaluate_script(discovery_script)
        if not menu_items:
            print("   ⚠️ 메뉴를 발견하지 못했습니다.")
            return []

        print(f"   ✅ {len(menu_items)}개 메뉴 발견")

        # 각 메뉴에 대해 보안 분석 수행
        analysis_results = []
        for i, menu in enumerate(menu_items[:max_pages]):
            print(f"📄 ({i+1}/{min(len(menu_items), max_pages)}) {menu['text']} 분석 중...")

            result = await analyze_page_security(menu['url'], menu['text'])
            analysis_results.append(result)

            # 분석 간 짧은 지연
            await asyncio.sleep(0.5)

        return analysis_results

    except Exception as e:
        print(f"   ❌ 메뉴 발견 실패: {e}")
        return []

async def perform_login(username: str, password: str) -> bool:
    """로그인 수행"""
    print("🔐 로그인 시도 중...")

    login_script = f"""
    () => {{
        const loginForms = document.querySelectorAll('form');

        for (const form of loginForms) {{
            const usernameField = form.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"]');
            const passwordField = form.querySelector('input[type="password"]');

            if (usernameField && passwordField) {{
                // 사용자명 입력
                usernameField.value = '{username}';
                usernameField.dispatchEvent(new Event('input', {{ bubbles: true }}));
                usernameField.dispatchEvent(new Event('change', {{ bubbles: true }}));

                // 비밀번호 입력
                passwordField.value = '{password}';
                passwordField.dispatchEvent(new Event('input', {{ bubbles: true }}));
                passwordField.dispatchEvent(new Event('change', {{ bubbles: true }}));

                // 폼 제출
                const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
                if (submitButton) {{
                    submitButton.click();
                    return {{ success: true, message: '로그인 폼 제출 완료' }};
                }} else {{
                    form.submit();
                    return {{ success: true, message: '폼 직접 제출 완료' }};
                }}
            }}
        }}

        return {{ success: false, message: '로그인 폼을 찾지 못함' }};
    }}
    """

    try:
        result = await playwright_evaluate_script(login_script)
        if result and result.get('success'):
            print(f"   ✅ {result['message']}")
            # 로그인 후 페이지 로딩 대기
            await asyncio.sleep(3)
            return True
        else:
            print(f"   ❌ {result.get('message', '로그인 실패') if result else '스크립트 실행 실패'}")
            return False
    except Exception as e:
        print(f"   ❌ 로그인 실행 실패: {e}")
        return False
```

### 3. 엑셀 보고서 생성기

```python
class SecurityReportGenerator:
    """보안 분석 결과 엑셀 보고서 생성기"""

    def __init__(self, analysis_results: List[Dict[str, Any]]):
        self.results = analysis_results
        self.excel_data = []
        self._prepare_excel_data()

    def _prepare_excel_data(self):
        """분석 결과를 엑셀 형식으로 변환"""
        for page_result in self.results:
            menu_name = page_result.get('menu', 'Unknown')
            url = page_result.get('url', '')
            page_info = page_result.get('page_info', {})

            vulnerabilities = page_result.get('vulnerabilities_found', [])

            if vulnerabilities:
                for vuln in vulnerabilities:
                    self.excel_data.append({
                        '메뉴': menu_name,
                        'URL': url,
                        '요소유형': vuln.get('elementType', 'unknown'),
                        '요소명': vuln.get('element', ''),
                        '파라미터': f"{vuln.get('elementType', '')}: {vuln.get('element', '')}",
                        'HTTP메소드': 'N/A',
                        '취약점종류': vuln.get('type', 'UNKNOWN'),
                        '위험도': vuln.get('severity', 'LOW'),
                        '상세설명': vuln.get('description', ''),
                        '패턴': vuln.get('pattern', 'unknown'),
                        '인증필요': 'Yes' if page_info.get('has_password_fields') else 'No',
                        '권장조치': self._get_recommendation(vuln)
                    })
            else:
                # 취약점 없는 경우도 기록
                self.excel_data.append({
                    '메뉴': menu_name,
                    'URL': url,
                    '요소유형': 'page',
                    '요소명': page_info.get('title', ''),
                    '파라미터': f"페이지 제목: {page_info.get('title', '')}",
                    'HTTP메소드': 'N/A',
                    '취약점종류': '없음',
                    '위험도': 'LOW',
                    '상세설명': '특별한 취약점 발견되지 않음',
                    '패턴': 'no_vulnerabilities',
                    '인증필요': 'Yes' if page_info.get('has_password_fields') else 'No',
                    '권장조치': '정기적인 보안 점검 권장'
                })

    def _get_recommendation(self, vulnerability: Dict[str, Any]) -> str:
        """취약점 유형별 권장조치"""
        vuln_type = vulnerability.get('type', '').upper()
        recommendations = {
            'XSS': '입력값 검증 및 출력값 인코딩 적용 필요',
            'CSRF': 'CSRF 토큰 구현 및 SameSite 쿠키 설정 필요',
            'SQL_INJECTION': 'PreparedStatement 또는 Parameterized Query 사용 필요',
            'PASSWORD_AUTOCOMPLETE': '비밀번호 필드에 autocomplete="off" 설정 필요',
            'MIXED_CONTENT': 'HTTPS 페이지에서는 HTTPS 링크만 사용 필요',
            'INSECURE_FORM_ACTION': 'HTTPS 페이지에서는 HTTPS 폼 전송 필요'
        }
        return recommendations.get(vuln_type, '상세한 보안 검토 필요')

    def create_excel_report(self) -> str:
        """엑셀 보고서 생성"""
        if not self.excel_data:
            print("⚠️ 보고서 생성할 데이터가 없습니다.")
            return ""

        try:
            # DataFrame 생성
            df = pd.DataFrame(self.excel_data)

            # 엑셀 파일명 생성
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            excel_filename = f"web_security_analysis_{timestamp}.xlsx"

            # Excel 파일 생성
            with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
                # 기본 보고서 시트
                df.to_excel(writer, sheet_name='보안분석결과', index=False)

                # 통계 요약 시트
                self._create_summary_sheet(writer, df)

                # 위험도별 분석 시트
                self._create_risk_analysis_sheet(writer, df)

            print(f"✅ 엑셀 보고서 생성 완료: {excel_filename}")
            return excel_filename

        except Exception as e:
            print(f"❌ 엑셀 보고서 생성 실패: {e}")
            return ""

    def _create_summary_sheet(self, writer: pd.ExcelWriter, df: pd.DataFrame):
        """요약 시트 생성"""
        summary_data = {
            '항목': ['총 분석 페이지', '총 발견 취약점', 'HIGH 위험도', 'MEDIUM 위험도', 'LOW 위험도'],
            '수량': [
                len(self.results),
                len(df[df['취약점종류'] != '없음']),
                len(df[df['위험도'] == 'HIGH']),
                len(df[df['위험도'] == 'MEDIUM']),
                len(df[df['위험도'] == 'LOW'])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='요약통계', index=False)

    def _create_risk_analysis_sheet(self, writer: pd.ExcelWriter, df: pd.DataFrame):
        """위험도별 분석 시트 생성"""
        # 취약점만 필터링
        vuln_df = df[df['취약점종류'] != '없음'].copy()

        if not vuln_df.empty:
            # 위험도별 그룹화
            risk_summary = vuln_df.groupby(['취약점종류', '위험도']).size().reset_index(name='발견건수')
            risk_summary = risk_summary.sort_values(['위험도', '발견건수'], ascending=[False, False])

            risk_summary.to_excel(writer, sheet_name='위험도분석', index=False)

    def create_csv_report(self) -> str:
        """CSV 보고서 생성"""
        if not self.excel_data:
            return ""

        try:
            # DataFrame 생성
            df = pd.DataFrame(self.excel_data)

            # CSV 파일명 생성
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_filename = f"web_security_analysis_{timestamp}.csv"

            # CSV 파일 생성 (UTF-8 인코딩)
            df.to_csv(csv_filename, index=False, encoding='utf-8-sig')

            print(f"✅ CSV 보고서 생성 완료: {csv_filename}")
            return csv_filename

        except Exception as e:
            print(f"❌ CSV 보고서 생성 실패: {e}")
            return ""

    def create_summary_report(self) -> Dict[str, Any]:
        """분석 결과 요약"""
        total_items = len(self.excel_data)
        high_risk = len([x for x in self.excel_data if x.get('위험도') == 'HIGH'])
        medium_risk = len([x for x in self.excel_data if x.get('위험도') == 'MEDIUM'])
        low_risk = len([x for x in self.excel_data if x.get('위험도') == 'LOW'])

        return {
            'total_items': total_items,
            'high_risk_count': high_risk,
            'medium_risk_count': medium_risk,
            'low_risk_count': low_risk,
            'total_pages': len(self.results),
            'vulnerability_rate': (high_risk + medium_risk) / total_items * 100 if total_items > 0 else 0
        }
```

### 4. 메인 실행 함수

```python
async def run_web_security_analysis(target_url: str, username: Optional[str] = None, password: Optional[str] = None) -> Dict[str, Any]:
    """웹 보안 분석 메인 실행 함수"""

    print("=" * 80)
    print("🛡️ 웹 보안 취약점 분석 스킬 시작")
    print("🔍 Playwright 기반 실제 브라우저 자동화 분석 수행")
    print("=" * 80)

    try:
        # 1. 초기화 및 페이지 접속
        print(f"\n🌐 {target_url} 접속 중...")

        # Playwright 페이지 생성
        try:
            await mcp__playwright__new_page(url=target_url)
            print("✅ 페이지 접속 성공")
        except Exception as e:
            print(f"❌ 페이지 접속 실패: {e}")
            return {'error': f'페이지 접속 실패: {str(e)}'}

        # 2. 로그인 처리 (필요시)
        if username and password:
            login_success = await perform_login(username, password)
            if login_success:
                print("✅ 로그인 성공 - 인증된 상태로 분석")
            else:
                print("⚠️ 로그인 실패 - 비인증 상태로 분석 진행")

        # 3. 메뉴 발견 및 보안 분석
        print(f"\n🔍 웹사이트 전체 메뉴 분석 시작...")
        analysis_results = await discover_menus_and_analyze(max_pages=ANALYSIS_CONFIG['max_pages'])

        if not analysis_results:
            print("⚠️ 분석 결과가 없습니다.")
            return {'warning': '분석할 페이지를 찾지 못했습니다.'}

        # 4. 보고서 생성
        print(f"\n📊 보고서 생성 중...")

        if analysis_results:
            generator = SecurityReportGenerator(analysis_results)
            excel_file = generator.create_excel_report()
            csv_file = generator.create_csv_report()

            # 요약 정보 출력
            summary = generator.create_summary_report()
            print(f"\n📈 분석 결과 요약:")
            print(f"   • 총 분석 페이지: {summary['total_pages']}개")
            print(f"   • 총 분석 항목: {summary['total_items']}개")
            print(f"   • HIGH 위험도: {summary['high_risk_count']}개")
            print(f"   • MEDIUM 위험도: {summary['medium_risk_count']}개")
            print(f"   • LOW 위험도: {summary['low_risk_count']}개")
            print(f"   • 취약점 발견율: {summary['vulnerability_rate']:.1f}%")

            if excel_file:
                print(f"   • 엑셀 보고서: {excel_file}")
            if csv_file:
                print(f"   • CSV 보고서: {csv_file}")

        print(f"\n✅ 웹 보안 분석 완료!")

        return {
            'success': True,
            'total_pages_analyzed': len(analysis_results),
            'total_vulnerabilities_found': sum(len(page.get('vulnerabilities_found', [])) for page in analysis_results),
            'analysis_results': analysis_results,
            'timestamp': datetime.now() + timedelta(hours=9)
        }

    except Exception as e:
        print(f"❌ 분석 중 오류 발생: {str(e)}")
        import traceback
        print(f"상세 오류: {traceback.format_exc()}")

        return {
            'error': f'분석 실패: {str(e)}',
            'traceback': traceback.format_exc()
        }

# 스킬 메인 실행 로직
if __name__ == "__main__":
    import sys
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8888/"
    username = sys.argv[2] if len(sys.argv) > 2 else None
    password = sys.argv[3] if len(sys.argv) > 3 else None

    asyncio.run(run_web_security_analysis(
        target_url=target_url,
        username=username,
        password=password
    ))
```

## 중요 사항

- 이 스킬은 실제 공격을 수행하지 않고 코드 패턴 분석만 수행
- 모든 분석은 Playwright를 통한 실제 사용자 상호작용 방식으로 진행
- 결과는 취약점 가능성을 나타내며, 전문가의 추가 검토 필요
- 분석 대상 사이트의 약관과 robots.txt 준수 필수
- CSV 파일 처리 시 인코딩 문제를 자동으로 해결하며, 한글(UTF-8, CP949, EUC-KR) 인코딩을 지원