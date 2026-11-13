import sys
sys.path.insert(0, '.')
from app.db.session import engine
from sqlalchemy import inspect, text

inspector = inspect(engine)
print('Tables:', inspector.get_table_names())
for table in inspector.get_table_names():
    print('  ' + table + ':')
    for col in inspector.get_columns(table):
        print('    ' + col['name'] + ': ' + str(col['type']))

from sqlalchemy import text
with engine.connect() as conn:
    result = conn.execute(text('SELECT * FROM sqlite_master WHERE type="table"'))
    print('sqlite_master:', result.fetchall())