from fastapi import Cookie, HTTPException
import boto3

from secret_keys import SecretKeys

secret_keys = SecretKeys()

cognito_client = boto3.client("cognito-idp", region_name=secret_keys.REGION_NAME)

def _get_user_from_cognito(access_token: str):
    try:
        user_res = cognito_client.get_user(AccessToken=access_token)

        return {
            attr['Name']: attr["Value"] for attr in user_res.get("UserAttributes", [])
        }
        

    except Exception as e:
        raise HTTPException(500, 'Error Fetching User')


def get_current_user(access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(401, 'Not Logged In')
    
    print(access_token)


    return _get_user_from_cognito(access_token)



