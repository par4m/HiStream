from fastapi import APIRouter, Depends, HTTPException
import boto3
from sqlmodel import Session
from db.db import get_session
from helper.auth_helper import get_secret_hash
from pydantic_models.auth_models import LoginRequest, SignupRequest
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

        return {"msg": "Signup successfull. Please verify your email if required"}

    except Exception as e:
        raise HTTPException(400,f"Cognito signup exception: {e}")





@router.post("/login")
async def login_user(data: LoginRequest, session: Session = Depends(get_session)):
    try:


        secret_hash = get_secret_hash(data.email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET)


        cognito_resp = cognito_client.initiate_auth(
        ClientId= COGNITO_CLIENT_ID,
             AuthParameters = {
                'USERNAME': data.email,
                'PASSWORD': data.password,
                'SECRET_HASH': secret_hash,

            }        )


       
        return cognito_resp

    except Exception as e:
        raise HTTPException(400,f"Cognito signup exception: {e}")





