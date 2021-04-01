import datetime
import sqlite3
from pathlib import Path

tcc_db_path = Path("~/Library/Application Support/com.apple.TCC/TCC.db").expanduser()
hopper_identifier = "com.cryptic-apps.hopper-web-4"
vscode_identifier = "com.microsoft.VSCode"

connection = sqlite3.connect(tcc_db_path.as_posix())
cursor = connection.cursor()

hopper_code_obj_identity = None

cursor.execute("select * from access")
for row in cursor.fetchall():
    entry_indirect_object_identifier = row[8]
    if entry_indirect_object_identifier == hopper_identifier:
        hopper_code_obj_identity = row[9]
        break

if hopper_code_obj_identity:
    cursor.execute(
        "insert into access VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "kTCCServiceAppleEvents",
            vscode_identifier,
            0,
            1,
            0,
            None,
            None,
            0,
            hopper_identifier,
            hopper_code_obj_identity,
            None,
            int(datetime.datetime.now().timestamp()),
        ),
    )
    
    connection.commit()
