#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
웹사이트 보안 분석 보고서 생성 스크립트
Chrome DevTools로 수집된 데이터를 기반으로 엑셀 보고서 생성
"""

import pandas as pd
from datetime import datetime, timezone
import json

def create_security_report():
    """보안 분석 결과를 엑셀 보고서로 생성"""

    # 분석 데이터
    analysis_data = {
        'basic_info': {
            'target_url': 'https://imgtopdf-web.vercel.app',
            'analysis_date': datetime.now(timezone('Asia/Seoul')).strftime('%Y-%m-%d %H:%M:%S'),
            'analyzer': 'Chrome DevTools MCP',
            'page_title': 'NoKeep - 이미지·PDF 변환 웹 앱'
        },

        'page_structure': {
            'main_headings': ['NoKeep', '업로드된 파일 (0/10)', '미리보기', '옵션'],
            'navigation_tabs': ['이미지', '추출', '병합', '분리', '서명'],
            'main_features': [
                '이미지 → PDF 변환',
                'PDF → 이미지 변환',
                'PDF 병합',
                'PDF 분리',
                '서명/도장 만들기'
            ],
            'total_buttons': 34,
            'file_inputs': 9
        },

        'security_analysis': {
            'https_enabled': True,
            'mixed_content': 0,
            'csp_header': None,
            'cookies_found': False,
            'localStorage_empty': True,
            'sessionStorage_empty': True
        },

        'network_analysis': {
            'total_requests': 10,
            'successful_requests': 9,
            'failed_requests': 1,
            'resource_types': {
                'document': 1,
                'script': 7,
                'stylesheet': 1,
                'image': 1
            },
            'static_resources': [
                '/_next/static/css/72d2326c0926b2b5.css',
                '/_next/static/chunks/webpack-7c05ac82a9e766ff.js',
                '/_next/static/chunks/4bd1b696-01f7aefb5200712e.js',
                '/_next/static/chunks/223-2580436733098fe6.js',
                '/_next/static/chunks/main-app-3d96b844cd9265c5.js',
                '/_next/static/chunks/app/layout-0b7f257b05210f36.js',
                '/_next/static/chunks/632-f91c28dba2e5f307.js',
                '/_next/static/chunks/app/page-14a38f3ab78eebea.js'
            ]
        },

        'vulnerability_assessment': {
            'high_risk': [],
            'medium_risk': [
                'CSP(Content Security Policy) 헤더 부재',
                '클라이언트 측 파일 처리로 인한 잠재적 메모리 누수'
            ],
            'low_risk': [
                'Canvas 성능 경고',
                '인라인 스크립트 사용'
            ],
            'observations': [
                '모든 파일이 클라이언트 측에서 처리됨',
                '서버에 파일이 영구 저장되지 않는다는 명시',
                'HTTPS 전용 통신',
                'Mixed Content 없음'
            ]
        },

        'forms_and_inputs': {
            'total_forms': 0,
            'file_inputs': [
                {'accept': 'image/jpeg,image/png,image/jpg', 'multiple': True, 'count': 2},
                {'accept': 'application/pdf', 'multiple': True, 'count': 6},
                {'accept': 'image/*', 'multiple': False, 'count': 1}
            ]
        },

        'privacy_features': {
            'client_side_processing': True,
            'no_server_storage': True,
            'privacy_policy_mentioned': True,
            'file_auto_deletion': True
        }
    }

    # 엑셀 파일 생성
    with pd.ExcelWriter('website_security_analysis.xlsx', engine='openpyxl') as writer:

        # 1. 요약 정보
        summary_data = {
            '항목': ['분석 대상', '분석 일시', '분석 도구', '페이지 제목', 'HTTPS 사용', 'Mixed Content', 'CSP 헤더'],
            '값': [
                analysis_data['basic_info']['target_url'],
                analysis_data['basic_info']['analysis_date'],
                analysis_data['basic_info']['analyzer'],
                analysis_data['basic_info']['page_title'],
                'O' if analysis_data['security_analysis']['https_enabled'] else 'X',
                analysis_data['security_analysis']['mixed_content'],
                'O' if analysis_data['security_analysis']['csp_header'] else 'X'
            ]
        }
        pd.DataFrame(summary_data).to_excel(writer, sheet_name='요약 정보', index=False)

        # 2. 보안 분석
        security_data = {
            '보안 항목': ['HTTPS 사용', 'Mixed Content', 'CSP 헤더', '쿠키 사용', 'LocalStorage', 'SessionStorage'],
            '상태': [
                '✅ 사용 중' if analysis_data['security_analysis']['https_enabled'] else '❌ 미사용',
                f'⚠️ {analysis_data["security_analysis"]["mixed_content"]}개 발견' if analysis_data['security_analysis']['mixed_content'] > 0 else '✅ 없음',
                '❌ 부재' if not analysis_data['security_analysis']['csp_header'] else '✅ 설정됨',
                '✅ 없음' if not analysis_data['security_analysis']['cookies_found'] else '⚠️ 있음',
                '✅ 비어있음' if analysis_data['security_analysis']['localStorage_empty'] else '⚠️ 데이터 있음',
                '✅ 비어있음' if analysis_data['security_analysis']['sessionStorage_empty'] else '⚠️ 데이터 있음'
            ],
            '위험도': ['낮음', '낮음', '중간', '낮음', '낮음', '낮음'],
            '설명': [
                '암호화된 통신 채널 사용',
                'HTTP/HTTPS 혼합 콘텐츠 없음',
                'XSS 공격 방지를 위한 CSP 헤더 필요',
                '추적 가능한 쿠키 없음',
                '클라이언트 측 저장소에 데이터 없음',
                '세션 저장소에 데이터 없음'
            ]
        }
        pd.DataFrame(security_data).to_excel(writer, sheet_name='보안 분석', index=False)

        # 3. 페이지 구조
        structure_data = {
            '구성 요소': ['메인 헤딩', '내비게이션 탭', '주요 기능', '전체 버튼 수', '파일 입력 필드'],
            '내용': [
                ', '.join(analysis_data['page_structure']['main_headings']),
                ', '.join(analysis_data['page_structure']['navigation_tabs']),
                f"{len(analysis_data['page_structure']['main_features'])}개 기능",
                f"{analysis_data['page_structure']['total_buttons']}개",
                f"{analysis_data['page_structure']['file_inputs']}개"
            ]
        }
        pd.DataFrame(structure_data).to_excel(writer, sheet_name='페이지 구조', index=False)

        # 4. 네트워크 분석
        network_data = {
            '리소스 타입': ['문서', '스크립트', '스타일시트', '이미지'],
            '요청 수': [
                analysis_data['network_analysis']['resource_types']['document'],
                analysis_data['network_analysis']['resource_types']['script'],
                analysis_data['network_analysis']['resource_types']['stylesheet'],
                analysis_data['network_analysis']['resource_types']['image']
            ]
        }
        pd.DataFrame(network_data).to_excel(writer, sheet_name='네트워크 분석', index=False)

        # 5. 취약점 평가
        vulnerability_data = {
            '위험도': ['높음', '중간', '낮음'],
            '취약점 수': [
                len(analysis_data['vulnerability_assessment']['high_risk']),
                len(analysis_data['vulnerability_assessment']['medium_risk']),
                len(analysis_data['vulnerability_assessment']['low_risk'])
            ],
            '내용': [
                '; '.join(analysis_data['vulnerability_assessment']['high_risk']) if analysis_data['vulnerability_assessment']['high_risk'] else '없음',
                '; '.join(analysis_data['vulnerability_assessment']['medium_risk']),
                '; '.join(analysis_data['vulnerability_assessment']['low_risk'])
            ]
        }
        pd.DataFrame(vulnerability_data).to_excel(writer, sheet_name='취약점 평가', index=False)

        # 6. 파일 입력 분석
        file_input_data = []
        for i, input_info in enumerate(analysis_data['forms_and_inputs']['file_inputs'], 1):
            file_input_data.append({
                '파일 입력 타입': input_info['accept'],
                '다중 선택': 'O' if input_info['multiple'] else 'X',
                '개수': input_info['count']
            })
        pd.DataFrame(file_input_data).to_excel(writer, sheet_name='파일 입력 분석', index=False)

        # 7. 개선 권고사항
        recommendations_data = {
            '우선순위': ['높음', '중간', '낮음'],
            '권고사항': [
                'CSP(Content Security Policy) 헤더 추가',
                'Canvas 성능 최적화 적용',
                '정기적인 보안 감사 실시'
            ],
            '상세 설명': [
                'XSS 공격 방지를 위해 CSP 헤더를 설정하여 스크립트 실행을 제어',
                'Canvas 요소에 willReadFrequently 속성 추가로 성능 경고 해결',
                '주기적인 취약점 점검 및 보안 패치 적용'
            ]
        }
        pd.DataFrame(recommendations_data).to_excel(writer, sheet_name='개선 권고사항', index=False)

        # 8. 프라이버시 특징
        privacy_data = {
            '프라이버시 특징': ['클라이언트 측 처리', '서버 저장 없음', '프라이버시 정책 언급', '자동 파일 삭제'],
            '상태': [
                '✅ 적용됨' if analysis_data['privacy_features']['client_side_processing'] else '❌ 미적용',
                '✅ 적용됨' if analysis_data['privacy_features']['no_server_storage'] else '❌ 미적용',
                '✅ 적용됨' if analysis_data['privacy_features']['privacy_policy_mentioned'] else '❌ 미적용',
                '✅ 적용됨' if analysis_data['privacy_features']['file_auto_deletion'] else '❌ 미적용'
            ]
        }
        pd.DataFrame(privacy_data).to_excel(writer, sheet_name='프라이버시 특징', index=False)

    print("보안 분석 보고서가 생성되었습니다: website_security_analysis.xlsx")
    return analysis_data

if __name__ == "__main__":
    result = create_security_report()
    print("\n분석 결과 요약:")
    print(f"HTTPS 사용: {'O' if result['security_analysis']['https_enabled'] else 'X'}")
    print(f"Mixed Content: {'있음' if result['security_analysis']['mixed_content'] > 0 else '없음'}")
    print(f"CSP 헤더: {'부재' if not result['security_analysis']['csp_header'] else '설정됨'}")
    print(f"파일 입력: {result['forms_and_inputs']['file_inputs']}개 유형")
    print(f"네트워크 요청: {result['network_analysis']['total_requests']}개")