"""Integration tests: register / login / lockout / refresh rotation / logout / me."""


def test_register_login_me_flow(client, make_user):
    account = make_user()
    assert account["data"]["user"]["roles"] == ["USER"]
    me = client.get("/api/v1/auth/me", headers=account["headers"])
    assert me.status_code == 200
    assert me.json()["email"] == account["email"]


def test_register_duplicate_email_conflict(client, make_user):
    account = make_user()
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": account["email"], "password": "Str0ngPassw0rd!"},
    )
    assert resp.status_code == 409


def test_register_weak_password_rejected(client, unique_email):
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": unique_email, "password": "alllowercase1"},
    )
    assert resp.status_code == 422


def test_login_unknown_email_is_generic_401(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "pytest_nobody@example.com", "password": "Whatever123!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"


def test_login_wrong_password_401(client, make_user):
    account = make_user()
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": account["email"], "password": "WrongPass123!"},
    )
    assert resp.status_code == 401


def test_lockout_after_repeated_failures(client, make_user):
    account = make_user()
    for _ in range(5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": account["email"], "password": "WrongPass123!"},
        )
        assert resp.status_code == 401
    # Even the CORRECT password is refused while the account is locked.
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": account["email"], "password": account["password"]},
    )
    assert resp.status_code == 423


def test_refresh_rotation(client, make_user):
    account = make_user()
    first_refresh = account["data"]["refresh_token"]

    rotated = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first_refresh}
    )
    assert rotated.status_code == 200
    new_refresh = rotated.json()["refresh_token"]
    assert new_refresh != first_refresh

    # The old token was rotated away - reuse is rejected.
    reuse = client.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
    assert reuse.status_code == 401

    ok = client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert ok.status_code == 200


def test_logout_revokes_session(client, make_user):
    account = make_user()
    body = {"refresh_token": account["data"]["refresh_token"]}
    resp = client.post("/api/v1/auth/logout", json=body, headers=account["headers"])
    assert resp.status_code == 200
    assert client.post("/api/v1/auth/refresh", json=body).status_code == 401


def test_me_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401
