from __future__ import annotations
import base64
import os
import json
from dotenv import load_dotenv
from datetime import datetime,timedelta
from typing import Optional,Tuple,List,Dict,Any
from fastapi import FastAPI,Query,HTTPException,Response
from pydantic import BaseModel
from sqlalchemy import (create_engine,select,and_,or_,desc,text,)
from sqlalchemy.orm import declarative_base,Session,Mapped,mapped_column
from sqlalchemy import Integer,String,DateTime

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL:", DATABASE_URL)
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class Item(Base):
    __tablename__ = "items"
    id: Mapped[int] = mapped_column(Integer,primary_key=True,autoincrement=True)
    name: Mapped[str] = mapped_column(String(255),nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime,nullable=False,index=True)

Base.metadata.create_all(engine)


app = FastAPI(title="Pagination",version="1.0.0")

def seed_data(total:int = 250) -> None:
    with Session(engine) as session:
        existing = session.scalar(select(text("COUNT(*)")).select_from(Item))
        if existing and existing >= total:
            print(f"Database already seeded with {existing} items.")
            return
        session.query(Item).delete()
        now = datetime.utcnow()
        for i in range(total):
            ts = now - timedelta(minutes=10*i)
            session.add(Item(name=f"Item {total - i:04d}",created_at=ts))
        session.commit()


seed_data()


def encode_cursor(created_at:datetime,id_:int) -> str:
    payload = {"created_at":created_at.isoformat(timespec="microseconds"),"id":id_}
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


def decode_cursor(cursor:str) -> Tuple[datetime,int]:
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        created_at = datetime.fromisoformat(payload["created_at"])
        return created_at,int(payload["id"])
    except Exception as e:
        raise HTTPException(status_code=400,detail="Invalid cursor")


def item_to_dict(it:Item) -> Dict[str,Any]:
    return {"id":it.id,"name":it.name,"created_at":it.created_at.isoformat()}