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

class ItemResponse(BaseModel):
    data : List[Dict[str,Any]]
    limit : int
    next_cursor : Optional[str] = None
    prev_cursor : Optional[str] = None
    offset : Optional[int] = None
    total : Optional[int] = None
    page : Optional[int] = None
    has_next : Optional[bool] = None


@app.get("/",tags=["meta"])
def root():
    return {
        "name":"Pagination API",
        "endpoints" : {
           "offset": "/items?limit=20&offset=0",
"page": "/items/page?limit=20&page=1",
"cursor": "/items/cursor?limit=20",
"time_window": "/items/time?start=2025-01-01T00:00:00Z&end=2025-01-02T00:00:00Z&limit=20",
        }
    }


#OFFSET BASED PAGINATION
@app.get("/items",response_model=ItemResponse,tags=["offset"])
def get_list_items_offset(response:Response,limit:int=Query(20,ge=1,le=100),offset:int=Query(0,ge=0)):
    with Session(engine) as session:
        rows = session.execute(select(Item).order_by(desc(Item.created_at),desc(Item.id)).limit(limit).offset(offset))
        rows = rows.scalars().all()

        total :int = session.scalar(select(text("COUNT(*)")).select_from(Item)) or 0
        has_next = (offset + limit) < total
        if has_next:
            next_offset = offset + limit
            response.headers["Link"] = f"</items?limit={limit}&offset={next_offset}>; rel=\"next\""
        return ItemResponse(
            data = [item_to_dict(r) for r in rows],
            limit = limit,
            offset = offset,
            total = total,
            has_next = has_next
        )
    

@app.get("/items/page",response_model = ItemResponse,tags=["offset"])
def list_items_page(response:Response,limit:int=Query(20,ge=1,le=100),page:int=Query(1,ge=1)):
    offset = (page - 1) * limit
    payload = get_list_items_offset(response,limit=limit,offset=offset)
    payload.page = page
    if payload.has_next:
        response.headers["Link"] = f"</items/page?limit={limit}&page={page+1}>; rel=\"next\""
    return payload


#CURSOR BASED PAGINATION
@app.get("/items/cursor",response_model=ItemResponse,tags=["cursor"])
def list_items_cursor(response:Response,limit:int=Query(20,ge=1,le=100),cursor:Optional[str]=None):
    with Session(engine) as session:
        q = select(Item).order_by(desc(Item.created_at),desc(Item.id))
        if cursor:
            created_at,id_ = decode_cursor(cursor)
            q = q.where(or_(Item.created_at < created_at, and_(Item.created_at == created_at,Item.id < id_)))
        rows = session.execute(q.limit(limit+1))
        rows = rows.scalars().all()
        has_next = len(rows) > limit
        rows = rows[:limit]
        next_cursor = encode_cursor(rows[-1].created_at,rows[-1].id) if has_next and rows else None
        if next_cursor:
            response.headers["Link"] = f"</items/cursor?limit={limit}&cursor={next_cursor}>; rel=\"next\""
        return ItemResponse(data=[item_to_dict(r) for r in rows],limit = limit,next_cursor=next_cursor,has_next=has_next)
