from sqlmodel import  Field, SQLModel

class User(SQLModel, table=True):
    # id =  Column(Integer, primary_key=True, index=True)
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(nullable=False)
    email: str = Field(nullable=False, unique=True, index=True)
    cognito_sub: str = Field(nullable=False, unique=True, index=True)

