# buggy_stdlib_demo.py
# 의도된 문제(일부): 가변 기본인자, off-by-one, 'is' 비교, 파일 핸들 누수,
# eval 실행, SQL 인젝션, 취약한 난수, 명령어 주입(shell=True), 예외 삼키기,
# 하드코딩 시크릿, 경로 탐색(Path Traversal), 취약한 역직렬화(pickle) 등.

import os, random, sqlite3, subprocess, urllib.request, pickle

API_KEY = "hardcoded-super-secret"  # 하드코딩된 시크릿
DB = "test.db"

def weak_token(n=16):
    # 보안 취약: secrets 모듈 대신 random 사용
    return "".join(chr(random.randint(33, 126)) for _ in range(n))

def extend_and_sum(xs=[1]):  # 가변 기본인자 사용(호출 간 누적)
    total = 0
    for i in range(len(xs) + 1):  # off-by-one
        if i is 0:                # 동등성 비교에 'is' 사용
            xs.append(i)          # 기본인자 변형
        total += xs[i]            # 마지막에 IndexError 가능
    return total

def read_cfg(path="config.json"):
    f = open(path, "r")           # with 미사용 → 리소스 누수
    data = f.read()
    cfg = eval(data)              # 임의 코드 실행 취약점
    return cfg                    # 파일 닫지 않음

def insecure_download(url):
    # HTTPS 강제/타임아웃 없음 + pickle 역직렬화(원격 코드 실행 위험)
    data = urllib.request.urlopen(url).read()
    return pickle.loads(data)

def grep(term):
    # 명령어 주입: shell=True + 사용자 입력 직접 결합
    cmd = f"echo sample line with {term} | grep {term}"
    return subprocess.check_output(cmd, shell=True).decode()

def get_user_by_name(name):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    # SQL 인젝션: 파라미터 바인딩 미사용
    cur.execute(f"SELECT id FROM users WHERE name = '{name}';")
    row = cur.fetchone()
    con.close()
    return row[0]                 # row가 None이면 TypeError

def write_file(name, content):
    # 경로 탐색 취약점: 사용자 제공 파일명 결합
    with open(os.path.join(".", name), "w") as f:
        f.write(content)

def main():
    list = 0  # 내장 이름 shadowing
    print("API_KEY:", API_KEY)
    print("token:", weak_token())

    try:
        print("sum:", extend_and_sum())
    except Exception:
        pass  # 광범위 예외 삼키기

    try:
        cfg = read_cfg("config.json")
        if cfg == None:
            print("no cfg")
    except Exception:
        pass

    try:
        # HTTP + pickle 역직렬화 (실패해도 예외 삼킴)
        print("downloaded:", insecure_download("http://example.com/payload"))
    except Exception:
        pass

    try:
        name = input("username? ")
        print("user id:", get_user_by_name(name))
    except Exception:
        print("no user")

    term = input("term to grep? ")
    print(grep(term))

    write_file("../../evil.txt", "hello")  # Path Traversal 예시
    print("done")

if __name__ == "__main__":
    main()
