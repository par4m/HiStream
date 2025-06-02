from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
import boto3
from sqlalchemy.orm.attributes import set_committed_value
from sqlmodel import Session
from db.db import get_session
from db.middleware.auth_middleware import get_current_user
from helper.auth_helper import get_secret_hash
from pydantic_models.auth_models import ConfirmSignupRequest, LoginRequest, SignupRequest
from db.models.user import User

from secret_keys import SecretKeys


router = APIRouter()
secret_keys = SecretKeys()

COGNITO_CLIENT_ID = secret_keys.COGNITO_CLIENT_ID
COGNITO_CLIENT_SECRET = secret_keys.COGNITO_CLIENT_SECRET

cognito_client = boto3.client("cognito-idp", region_name=secret_keys.REGION_NAME)
@router.post("/signup")
async def signup_user(data: SignupRequest, session: Session = Depends(get_session)):
    try:


        secret_hash = get_secret_hash(data.email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET)


        cognito_resp = cognito_client.sign_up(
        ClientId= COGNITO_CLIENT_ID,
            Username = data.email,
            Password=data.password,
            SecretHash=secret_hash,
            UserAttributes = [
                {'Name': "email", 'Value': data.email},
                {'Name': "name", 'Value': data.name},
            ]
        )

        cognito_sub = cognito_resp.get("UserSub")
        if not cognito_sub:
            raise HTTPException(400, "Cognito did not return a valid user sub")

        new_user =  User(name=data.name, email=data.email,cognito_sub=cognito_sub)
        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        return {"message": "Signup successfull. Please verify your email if required"}

    except Exception as e:
        raise HTTPException(400,f"Cognito signup exception: {e}")





@router.post("/login")
async def login_user(data: LoginRequest, response: Response):
    try:


        secret_hash = get_secret_hash(data.email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET)


        cognito_resp = cognito_client.initiate_auth(
        ClientId= COGNITO_CLIENT_ID,
        AuthFlow="USER_PASSWORD_AUTH",
             AuthParameters = {
                'USERNAME': data.email,
                'PASSWORD': data.password,
                'SECRET_HASH': secret_hash,

            })

        auth_result = cognito_resp.get("AuthenticationResult")

        if not auth_result:
            raise HTTPException(400, "Incorrect Cognito Response")

        access_token = auth_result.get("AcessToken")
        refresh_token = auth_result.get("RefreshToken")

        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
        response.set_cookie(key="refresh_token", value=access_token, httponly=True, secure=True)




       
        return cognito_resp

    except Exception as e:
        raise HTTPException(400,f"Cognito Login exception: {e}")



@router.post("/confirm-signup")
async def confirm_signup(data: ConfirmSignupRequest):
    try:
        secret_hash = get_secret_hash(data.email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET)
        cognito_resp = cognito_client.confirm_sign_up(
        ClientId= COGNITO_CLIENT_ID,
        Username= data.email,
        ConfirmationCode = data.otp,
            SecretHash=secret_hash
                 )
        return {"message": "User confirmed successfully"}

    except Exception as e:
        raise HTTPException(400,f"Cognito signup exception: {e}")



@router.post("/refresh")
async def refresh_token(refresh_token: str = Cookie(None) , user_cognito_sub: str = Cookie(None) ,response: Response = None):
    try:
        secret_hash = get_secret_hash(user_cognito_sub, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET)
        cognito_resp = cognito_client.initiate_auth(
        ClientId= COGNITO_CLIENT_ID,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters = {
                'REFRESH_TOKEN': refresh_token, 'SECRET_HASH': secret_hash
            },
        
        )

        auth_result = cognito_resp.get("AuthenticationResult")

        if not auth_result:
            raise HTTPException(400, "Incorrect Cognito Response")

        access_token = auth_result.get("AcessToken")
        refresh_token = auth_result.get("RefreshToken")

        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
        response.set_cookie(key="refresh_token", value=access_token, httponly=True, secure=True)


        return {'message': 'Access token refreshed!'}

    except Exception as e:
        raise HTTPException(400,f"Cognito signup exception: {e}")





@router.get("/me")
def protected_route(user = Depends(get_current_user)):
    return {"Message": "You are authenticated", "user": user}








