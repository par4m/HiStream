from sqlmodel import create_engine, Session, SQLModel

from db.models import user
from secret_keys import SecretKeys



secret_keys = SecretKeys()



engine = create_engine(secret_keys.POSTGRES_DB_URL, echo=True)



def init_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(autocommit=False, autoflush=False,bind=engine) as session:
        yield session


