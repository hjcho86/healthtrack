# HealthTrack

건강검진 결과를 연도별로 입력하면 통계·추이를 한눈에 보고, 검사 항목을 검색해 해당 추이를 바로 확인하는 웹 서비스.

- 요약 / 연도별 표 / 추이 차트 / 항목 상세 / 검색(이름·별칭·초성·연도·판정) / 입력(일괄 붙여넣기 지원)
- 순수 정적 사이트(빌드 없음). 데이터는 **브라우저 localStorage에만** 저장되며 서버로 전송되지 않음
- 기기 이전·백업: 설정 탭의 JSON/CSV 내보내기·가져오기
- 판정 기준은 국가건강검진 기준을 참고한 일반 참고치이며 의학적 진단이 아님 (`catalog.js`에서 수정)

## 로컬 실행
```bash
python3 -m http.server 8810
# http://localhost:8810
```

## 배포
`main`에 push하면 GitHub Pages(`.github/workflows/pages.yml`)가 자동 배포.
