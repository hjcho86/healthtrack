# HealthTrack

건강검진 결과를 연도별로 입력하면 통계·추이를 한눈에 보고, 검사 항목을 검색해 해당 추이를 바로 확인하는 웹 서비스.
기록은 **비밀번호로 암호화되어 서버(Cloudflare D1)에 저장**되고, 서버는 비밀번호도 기록 내용도 알 수 없습니다.

## 구조
- `public/` — 정적 프런트엔드(빌드 없음)
- `src/worker.js` — API(로그인 토큰 검증, 암호문 저장, 연속 실패 시 시도 제한)
- `schema.sql` — D1 스키마(+ '쭌' 계정: 처음 접속한 사람이 비밀번호를 정함)
- 암호화: PBKDF2(200k) → AES-GCM(브라우저). 서버 로그인용 토큰은 암호화 키와 별개로 유도하며 서버엔 그 해시만 저장
- 새 계정은 서버에 미리 만들어 두는 방식(공개 가입 없음). 앱의 “+ 이름 추가”는 이 브라우저 목록에만 이름을 추가

## 로컬 실행
```bash
npm run db:local     # 로컬 D1 스키마 적용
npm run dev          # http://localhost:8810
```

## 배포 (Cloudflare)
```bash
npx wrangler login
npx wrangler d1 create healthtrack      # 출력된 database_id를 wrangler.toml에 입력
npm run db:remote
npm run deploy
```
계정 추가: `INSERT INTO accounts (name, auth_salt) VALUES ('이름', '임의의 base64 salt');` 후 해당 이름으로 접속해 비밀번호를 정함.

## 백업
설정 탭의 JSON 내보내기(평문 주의). 서버 DB는 `wrangler d1 export healthtrack --remote --output backup.sql`로 암호문 그대로 백업 가능.

판정 기준은 국가건강검진 기준을 참고한 일반 참고치이며 진단이 아닙니다(`public/catalog.js`).
