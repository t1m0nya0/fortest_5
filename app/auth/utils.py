# dependencies.py
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt


def parse_jwt_data(token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token"))) -> dict:
    try:
        payload = jwt.decode(token, "JWT_SECRET", algorithms=["HS256"])
    except JWTError:
        raise InvalidCredentials()

    return {"user_id": payload["id"]}
