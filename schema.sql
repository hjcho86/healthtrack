-- 계정 한 줄 = 사람 한 명. 서버는 비밀번호도 평문 기록도 모르고, 암호문(blob)과 검증값(verifier)만 가진다.
CREATE TABLE IF NOT EXISTS accounts (
  name         TEXT PRIMARY KEY,
  auth_salt    TEXT NOT NULL,
  verifier     TEXT,                       -- sha256(로그인 토큰). NULL이면 아직 주인이 비밀번호를 정하지 않은 계정
  blob         TEXT,                       -- 브라우저에서 암호화한 기록(JSON 문자열)
  version      INTEGER NOT NULL DEFAULT 0, -- 동시 수정 충돌 방지
  fails        INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL DEFAULT 0
);
-- '쭌' 계정: 처음 접속한 사람이 비밀번호를 정하면 그 사람 것이 된다.
INSERT OR IGNORE INTO accounts (name, auth_salt) VALUES ('쭌', 'anVuLWluaXRpYWwtc2FsdC0wMQ==');
