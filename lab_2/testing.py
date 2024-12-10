from fastapi.testclient import TestClient
from main import app
import time


client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200

def test_get_users():
    # Создаем пользователя для теста
    response = client.post(
        "/register/",
        json={"username": "testuser", "email": "testuser@example.com", "full_name": "Test User", "password": "password123"},
    )
    assert response.status_code == 200

    # Получаем список пользователей
    response = client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert data[0]["username"] == "testuser"

def test_create_user():
    response = client.post(
        "/register/",
        json={"username": "testuser2", "email": "testuser2@example.com", "full_name": "Test User 2", "password": "password123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser2"
    assert data["email"] == "testuser2@example.com"

def test_login_for_access_token():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "password123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_read_users_me():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "password123"},
    )
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"

def test_update_user():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "password123"},
    )
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.put(
        "/users/1",
        headers=headers,
        json={"full_name": "Updated Test User"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Updated Test User"

def test_delete_user():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "password123"},
    )
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.delete("/users/1", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"

def test_cors():
    response = client.options("/users/")
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" in response.headers
    assert response.headers["Access-Control-Allow-Origin"] == "*"

def test_create_user_missing_field():
    response = client.post(
        "/register/",
        json={"username": "testuser", "email": "testuser@example.com"},
    )
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert data["detail"][0]["msg"] == "field required"

def test_create_user_duplicate_username():
    # Создаем пользователя для теста
    response = client.post(
        "/register/",
        json={"username": "testuser", "email": "testuser@example.com", "full_name": "Test User", "password": "password123"},
    )
    assert response.status_code == 200

    # Повторная регистрация с тем же username
    response = client.post(
        "/register/",
        json={"username": "testuser", "email": "testuser2@example.com", "full_name": "Test User 2", "password": "password123"},
    )
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Username or Email already registered"

def test_create_user_duplicate_email():
    # Создаем пользователя для теста
    response = client.post(
        "/register/",
        json={"username": "testuser", "email": "testuser@example.com", "full_name": "Test User", "password": "password123"},
    )
    assert response.status_code == 200

    # Повторная регистрация с тем же email
    response = client.post(
        "/register/",
        json={"username": "testuser2", "email": "testuser@example.com", "full_name": "Test User 2", "password": "password123"},
    )
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Username or Email already registered"

def test_performance():
    start_time = time.time()
    for _ in range(100):
        response = client.get("/users/")
        assert response.status_code == 200
    end_time = time.time()
    elapsed_time = end_time - start_time
    assert elapsed_time < 5  # Убедитесь, что время отклика меньше 5 секунд для 100 запросов

def test_unauthorized_access():
    response = client.get("/users/me")
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Could not validate credentials"

def test_invalid_token():
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Could not validate credentials"