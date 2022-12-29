from datetime import datetime, timedelta
from typing import Union
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import uvicorn

# secret_key 在安装了openssl相关组件后通过 openssl rand -hex 32 命令来生成，生产环境需要替换此key
SECRET_KEY = 'bb6fbc27db65d506805dc3cbbe00ee9a526e4ce1892830c215acebe3528f90a4'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_DAYS = 30

# 预置的用户信息
fake_users_db = {
    'nyasama': {
        'username': 'nyasama',
        'full_name': 'nyasama-admin',
        'email': 'admin@nyasama.com',
        'hashed_password': '$2b$12$khkSAxC44oam/i7.yni.7O20U5Voru4zvuDneO9dUbd8Q1nhUH.bK',
        'disabled': False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

app = FastAPI()
app.add_middleware(
    CORSMiddleware,

    # 允许跨域的源列表，例如 ['http://www.example.org'] 等等，['*'] 表示允许任何源
    allow_origins=[
        '*'
    ],

    # 跨域请求是否支持 cookie，默认是 False，如果为 True，allow_origins 必须为具体的源，不可以是 ['*']
    allow_credentials=False,

    # 允许跨域请求的 HTTP 方法列表，默认是 ['GET']
    allow_methods=['GET'],

    # 允许跨域请求的 HTTP 请求头列表，默认是 []，可以使用 ['*'] 表示允许所有的请求头
    # 当然 Accept、Accept-Language、Content-Language 以及 Content-Type 总是被允许的
    allow_headers=['*'],
)


def verify_password(plain_password, hashed_password):
    """
    :param plain_password: 用户原始密码
    :param hashed_password: 数据库中存储的hash之后的密码
    """

    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """
    :param password: 将传入的密码进行hash
    """

    return pwd_context.hash(password)


def get_user(db, username: str):
    """
    :param db: 数据库
    :param username: 用户名
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    """
    :param fake_db: 数据库
    :param username: 用户名
    :param password: 密码
    :return: 用户信息
    """

    user = get_user(fake_db, username)

    if not user:
        return False

    if not verify_password(password, user.hashed_password):
        return False

    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    """
    :param data: 用于创建 token 的字典，{'sub': $username}
    :param expires_delta: token的过期时间
    :return: jwt令牌
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username: str = payload.get('sub')

        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user(fake_users_db, username=token_data.username)

    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail='Inactive user')

    return current_user


@app.post('/login', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    登录接口
    :param form_data: 登录信息
    """
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)

    access_token = create_access_token(
        data={'sub': user.username}, expires_delta=access_token_expires
    )

    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get('/users/me/', response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get('/users/me/items/')
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{'item_id': 'Foo', 'owner': current_user.username}]


if __name__ == '__main__':
    uvicorn.run(app='main:app', host='localhost', port=8080, reload=True)
