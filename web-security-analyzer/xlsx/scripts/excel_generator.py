#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
엑셀 보고서 생성 스크립트
웹 보안 분석 결과를 엑셀 파일로 생성
"""

import pandas as pd
import openpyxl
from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.chart import BarChart, Reference
import json
from datetime import datetime
import os
from typing import Dict, List, Any

class ExcelReportGenerator:
    """웹 보안 분석 결과 엑셀 보고서 생성기"""

    def __init__(self, analysis_results: Dict[str, Any]):
        self.analysis_results = analysis_results
        self.workbook = None
        self.current_row = 1

    def create_detailed_report(self, output_filename: str = None) -> str:
        """메뉴별 상세 보고서 생성 함수"""

        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"web_security_analysis_{timestamp}.xlsx"

        # 워크북 생성
        self.workbook = openpyxl.Workbook()

        # 기본 시트 삭제
        self.workbook.remove(self.workbook.active)

        # 메뉴별 상세 분석 시트 생성
        self._create_menu_based_analysis_sheet()

        # 요약 시트 생성
        self._create_summary_sheet()
        self._create_vulnerability_summary_sheet()

        # 파일 저장
        self.workbook.save(output_filename)
        print(f"Detailed Excel report created: {output_filename}")

        return output_filename

    def _create_menu_based_analysis_sheet(self):
        """메뉴별 상세 분석 시트 생성"""
        ws = self.workbook.create_sheet("메뉴별 상세 분석")

        # 제목
        self._add_title(ws, "메뉴별 웹 보안 상세 분석")

        # 헤더 행 정의
        headers = [
            "메뉴", "URL", "요소유형", "요소명", "파라미터",
            "HTTP메소드", "취약점종류", "위험도", "상세설명",
            "패턴", "인증필요", "권장조치"
        ]

        # 헤더 추가
        for col_idx, header in enumerate(headers, 1):
            cell = ws.cell(row=self.current_row, column=col_idx, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.border = Border(
                left=Side(style="thin"), right=Side(style="thin"),
                top=Side(style="thin"), bottom=Side(style="thin")
            )

        self.current_row += 1

        # 데이터 처리
        if isinstance(self.analysis_results, list):
            # 새로운 형식: 리스트 형태의 분석 데이터
            data_rows = self.analysis_results
        else:
            # 기존 형식을 새로운 형식으로 변환
            data_rows = self._convert_legacy_format(self.analysis_results)

        # 데이터 행 추가
        for row_data in data_rows:
            for col_idx, header in enumerate(headers, 1):
                value = row_data.get(header, "")
                if value is None:
                    value = ""

                cell = ws.cell(row=self.current_row, column=col_idx, value=value)

                # 위험도에 따른 색상 지정
                if header == "위험도":
                    if str(value).upper() == "HIGH":
                        cell.fill = PatternFill(start_color="FFE6E6", end_color="FFE6E6", fill_type="solid")
                    elif str(value).upper() == "MEDIUM":
                        cell.fill = PatternFill(start_color="FFF4E6", end_color="FFF4E6", fill_type="solid")
                    elif str(value).upper() == "LOW":
                        cell.fill = PatternFill(start_color="E6F3FF", end_color="E6F3FF", fill_type="solid")

                # 테두리 추가
                cell.border = Border(
                    left=Side(style="thin"), right=Side(style="thin"),
                    top=Side(style="thin"), bottom=Side(style="thin")
                )

                # 정렬
                if header in ["메뉴", "요소유형", "취약점종류", "위험도", "인증필요"]:
                    cell.alignment = Alignment(horizontal="center")
                elif header in ["상세설명", "권장조치"]:
                    cell.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)

            self.current_row += 1

        # 열 너비 자동 조정
        column_widths = [15, 40, 10, 30, 25, 12, 15, 10, 50, 25, 10, 30]
        for col_idx, width in enumerate(column_widths, 1):
            ws.column_dimensions[openpyxl.utils.get_column_letter(col_idx)].width = width

        # 필터 추가
        ws.auto_filter.ref = f"A1:{openpyxl.utils.get_column_letter(len(headers))}{self.current_row - 1}"

        # 셀 고정 (헤더 행)
        ws.freeze_panes = "A2"

    def _create_vulnerability_summary_sheet(self):
        """취약점 요약 시트 생성"""
        ws = self.workbook.create_sheet("취약점 요약")

        # 제목
        self._add_title(ws, "취약점 종류별 요약")

        # 데이터 처리
        if isinstance(self.analysis_results, list):
            data_rows = self.analysis_results
        else:
            data_rows = self._convert_legacy_format(self.analysis_results)

        # 취약점 종류별 통계
        vuln_stats = {}
        severity_stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        type_stats = {}

        for row in data_rows:
            vuln_type = row.get("취약점종류", "")
            severity = str(row.get("위험도", "")).upper()

            if vuln_type:
                type_stats[vuln_type] = type_stats.get(vuln_type, 0) + 1

            if severity in severity_stats:
                severity_stats[severity] += 1

        # 위험도별 통계 테이블
        self._add_subtitle(ws, "위험도별 분포")

        severity_data = [
            ["위험도", "개수", "비율(%)"],
            ["HIGH", severity_stats["HIGH"], ""],
            ["MEDIUM", severity_stats["MEDIUM"], ""],
            ["LOW", severity_stats["LOW"], ""],
            ["총계", sum(severity_stats.values()), "100.0"]
        ]

        # 비율 계산
        total = sum(severity_stats.values())
        if total > 0:
            severity_data[1][2] = f"{severity_stats['HIGH']/total*100:.1f}"
            severity_data[2][2] = f"{severity_stats['MEDIUM']/total*100:.1f}"
            severity_data[3][2] = f"{severity_stats['LOW']/total*100:.1f}"

        self._add_table(ws, severity_data)

        # 취약점 종류별 통계
        if type_stats:
            self.current_row += len(severity_data) + 2
            self._add_subtitle(ws, "취약점 종류별 분포")

            type_data = [["취약점 종류", "개수"]]
            for vuln_type, count in sorted(type_stats.items(), key=lambda x: x[1], reverse=True):
                type_data.append([vuln_type, count])

            self._add_table(ws, type_data)

        # 권장 조치 요약
        self.current_row += len(type_data) + 2
        self._add_subtitle(ws, "주요 권장 조치")

        recommendations = {}
        for row in data_rows:
            action = row.get("권장조치", "")
            if action:
                recommendations[action] = recommendations.get(action, 0) + 1

        if recommendations:
            rec_data = [["권장 조치", "발생 빈도"]]
            for action, count in sorted(recommendations.items(), key=lambda x: x[1], reverse=True)[:10]:
                rec_data.append([action, count])

            self._add_table(ws, rec_data)

    def _create_summary_sheet(self):
        """요약 정보 시트 생성"""
        ws = self.workbook.create_sheet("요약 정보")

        # 제목
        self._add_title(ws, "웹 보안 분석 보고서 요약")

        # 기본 정보
        if isinstance(self.analysis_results, list):
            # 새로운 형식의 데이터 처리
            summary_data = [
                ["분석 대상", "웹사이트 전체"],
                ["분석 시간", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ["총 분석 항목", len(self.analysis_results)],
                ["분석 방식", "Chrome DevTools + 패턴 분석"],
            ]

            # 위험도별 통계
            severity_stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for row in self.analysis_results:
                severity = str(row.get("위험도", "")).upper()
                if severity in severity_stats:
                    severity_stats[severity] += 1

            summary_data.extend([
                ["HIGH 위험도 취약점", severity_stats["HIGH"]],
                ["MEDIUM 위험도 취약점", severity_stats["MEDIUM"]],
                ["LOW 위험도 취약점", severity_stats["LOW"]],
                ["총 취약점", sum(severity_stats.values())]
            ])
        else:
            # 기존 형식의 데이터 처리
            basic_info = self.analysis_results.get('basic_info', {})
            security_info = self.analysis_results.get('security', {})

            summary_data = [
                ["분석 대상 URL", basic_info.get('url', 'N/A')],
                ["사이트 제목", basic_info.get('title', 'N/A')],
                ["분석 시간", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ["프로토콜", basic_info.get('protocol', 'N/A')],
                ["HTTPS 사용", "예" if security_info.get('isHTTPS') else "아니오"],
                ["총 폼 수", len(self.analysis_results.get('forms', []))],
                ["내부 링크 수", self.analysis_results.get('navigation', {}).get('internalLinks', 0)],
            ]

        self._add_table(ws, summary_data, start_col=1, start_row=self.current_row)

    def _convert_legacy_format(self, legacy_data):
        """기존 형식의 데이터를 새로운 형식으로 변환"""
        converted_data = []

        # 기존 형식에서 데이터 추출
        forms = legacy_data.get('forms', [])
        network = legacy_data.get('network', {})
        vulnerabilities = legacy_data.get('vulnerabilities', {})

        # 폼 데이터 변환
        for i, form in enumerate(forms):
            # 각 폼에 대한 기본 정보
            form_base = {
                "메뉴": f"폼 #{i+1}",
                "URL": legacy_data.get('basic_info', {}).get('url', ''),
                "요소유형": "FORM",
                "요소명": form.get('action', ''),
                "파라미터": ', '.join([f"{field.get('name', '')}({field.get('type', '')})" for field in form.get('fields', [])]),
                "HTTP메소드": form.get('method', '').upper(),
                "인증필요": "Yes" if legacy_data.get('security', {}).get('isHTTPS') else "No"
            }

            # 폼의 잠재적 취약점
            for vuln in form.get('potentialVulnerabilities', []):
                vuln_row = form_base.copy()
                vuln_row.update({
                    "취약점종류": vuln.get('type', ''),
                    "위험도": vuln.get('severity', ''),
                    "상세설명": vuln.get('description', ''),
                    "패턴": vuln.get('pattern', ''),
                    "권장조치": self._get_recommendation_by_type(vuln.get('type', ''))
                })
                converted_data.append(vuln_row)

            # 취약점이 없는 경우도 추가
            if not form.get('potentialVulnerabilities'):
                form_base.update({
                    "취약점종류": "없음",
                    "위험도": "LOW",
                    "상세설명": "특별한 취약점이 발견되지 않음",
                    "패턴": "-",
                    "권장조치": "정기적인 보안 점검 권장"
                })
                converted_data.append(form_base)

        # 네트워크/API 데이터 변환
        api_endpoints = network.get('apiEndpoints', [])
        for api in api_endpoints:
            api_row = {
                "메뉴": "API 호출",
                "URL": legacy_data.get('basic_info', {}).get('url', ''),
                "요소유형": "API",
                "요소명": api.get('url', ''),
                "파라미터": "API_Endpoint",
                "HTTP메소드": api.get('method', ''),
                "취약점종류": "API_ENDPOINT",
                "위험도": "MEDIUM",
                "상세설명": f"API 엔드포인트 발견: {api.get('url', '')}",
                "패턴": "api_call",
                "인증필요": "Yes" if legacy_data.get('security', {}).get('isHTTPS') else "No",
                "권장조치": "API 인증 및 접근 제어 검토 필요"
            }
            converted_data.append(api_row)

        return converted_data

    def _get_recommendation_by_type(self, vuln_type):
        """취약점 타입별 권장 조치 반환"""
        recommendations = {
            'XSS': '입력값 검증 및 출력값 인코딩 적용',
            'SQL_INJECTION': 'Prepare Statement 또는 Parameterized Query 사용',
            'CSRF': 'CSRF 토큰 구현 및 검증',
            'AUTHORIZATION': '적절한 인증 및 권한 체계 구현',
            'INFORMATION_DISCLOSURE': '일반화된 에러 메시지 사용',
            'SECURITY_HEADERS': '보안 관련 HTTP 헤더 설정',
            'MIXED_CONTENT': '모든 리소스 HTTPS로 전환',
            'WEAK_PASSWORD': '강력한 비밀번호 정책 적용',
            'SESSION_MANAGEMENT': '안전한 세션 관리 구현'
        }
        return recommendations.get(vuln_type, '상세한 보안 검토 필요')

    # 보조 메소드들
    def _add_title(self, ws, title):
        """제목 추가"""
        cell = ws.cell(row=self.current_row, column=1, value=title)
        cell.font = Font(bold=True, size=16, color="366092")
        self.current_row += 2

    def _add_subtitle(self, ws, subtitle):
        """부제목 추가"""
        cell = ws.cell(row=self.current_row, column=1, value=subtitle)
        cell.font = Font(bold=True, size=12)
        self.current_row += 1

    def _add_table(self, ws, data, start_col=1, start_row=None):
        """테이블 추가"""
        if start_row is None:
            start_row = self.current_row

        for row_idx, row_data in enumerate(data, start_row):
            for col_idx, value in enumerate(row_data, start_col):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                if row_idx == start_row:  # 헤더 행
                    cell.font = Font(bold=True)
                    cell.fill = PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid")
                cell.border = Border(
                    left=Side(style="thin"), right=Side(style="thin"),
                    top=Side(style="thin"), bottom=Side(style="thin")
                )

        self.current_row = start_row + len(data) + 1

def main():
    """테스트용 메인 함수"""
    # 새로운 형식의 테스트 데이터
    test_data = [
        {
            "메뉴": "로그인",
            "URL": "https://example.com/login",
            "요소유형": "FORM",
            "요소명": "/login",
            "파라미터": "username(text), password(password)",
            "HTTP메소드": "POST",
            "취약점종류": "XSS",
            "위험도": "MEDIUM",
            "상세설명": "입력값 검증 부재로 XSS 가능성",
            "패턴": "input_validation_missing",
            "인증필요": "Yes",
            "권장조치": "입력값 검증 및 출력값 인코딩 적용"
        },
        {
            "메뉴": "회원가입",
            "URL": "https://example.com/register",
            "요소유형": "FORM",
            "요소명": "/register",
            "파라미터": "email(text), password(password), name(text)",
            "HTTP메소드": "POST",
            "취약점종류": "CSRF",
            "위험도": "MEDIUM",
            "상세설명": "CSRF 토큰 부재",
            "패턴": "missing_csrf_token",
            "인증필요": "No",
            "권장조치": "CSRF 토큰 구현 및 검증"
        },
        {
            "메뉴": "게시판",
            "URL": "https://example.com/board",
            "요소유형": "API",
            "요소명": "/api/posts",
            "파라미터": "page, limit",
            "HTTP메소드": "GET",
            "취약점종류": "INFORMATION_DISCLOSURE",
            "위험도": "LOW",
            "상세설명": "상세 에러 메시지 노출",
            "패턴": "detailed_error_exposure",
            "인증필요": "No",
            "권장조치": "일반화된 에러 메시지 사용"
        }
    ]

    generator = ExcelReportGenerator(test_data)
    output_file = generator.create_detailed_report("test_detailed_security_report.xlsx")
    print(f"상세 분석 테스트 보고서 생성: {output_file}")

if __name__ == "__main__":
    main()