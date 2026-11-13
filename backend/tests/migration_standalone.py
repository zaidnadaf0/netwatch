import tempfile
import os
import time
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

# Create a unique temporary database file path (don't create the file yet)
temp_db_path = os.path.join(tempfile.gettempdir(), f'test_migration_{os.getpid()}_{int(time.time()*1000)}.db')

# Ensure the file doesn't exist
if os.path.exists(temp_db_path):
    os.unlink(temp_db_path)

temp_db_path = os.path.abspath(temp_db_path)

# Set the database URL environment variable BEFORE importing settings
os.environ['NETWATCH_DATABASE_URL'] = f'sqlite:///{temp_db_path}'

# Use absolute path for alembic.ini
alembic_ini_path = os.path.join(os.path.dirname(__file__), '..', 'alembic.ini')
alembic_cfg = Config(alembic_ini_path)
alembic_cfg.set_main_option('sqlalchemy.url', f'sqlite:///{temp_db_path}')

print('Script location:', alembic_cfg.get_main_option('script_location'))
print('SQLAlchemy URL:', alembic_cfg.get_main_option('sqlalchemy.url'))

from alembic import command
command.upgrade(alembic_cfg, 'head')

temp_engine = create_engine(f'sqlite:///{temp_db_path}', connect_args={'check_same_thread': False})
from sqlalchemy import inspect
inspector = inspect(temp_engine)
tables = inspector.get_table_names()
print('Tables after upgrade:', tables)
assert 'flow_logs' in tables
assert 'detection_events' in tables
assert 'security_group_audits' in tables

command.downgrade(alembic_cfg, 'base')

inspector = inspect(temp_engine)
tables = inspector.get_table_names()
print('Tables after downgrade:', tables)
assert 'flow_logs' not in tables
assert 'detection_events' not in tables
assert 'security_group_audits' not in tables

print('Migration test passed!')