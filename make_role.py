# Helper script for creating an Admin or Complaint Team member.
import sqlite3
from werkzeug.security import generate_password_hash

DB = 'loopify.db'
print("Create Role in Loopify")
print("1. Admin")
print("2. Complaint Team Member")
choice = input("Select role (1/2 or admin/complaint_team) [1]: ").strip().lower()

c = sqlite3.connect(DB)

if choice in ('1', 'admin', ''):
    name = input("Admin Name: ").strip()
    email = input("Admin Email: ").strip().lower()
    phone = input("Admin Phone: ").strip()
    password = input("Password (min 6 chars): ").strip()
    if not name or not email or len(password) < 6:
        c.close()
        raise SystemExit("Name, email and password (min 6 chars) are required.")
    try:
        c.execute("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)",
                  (name, email, phone, generate_password_hash(password), 'admin'))
        c.commit()
        print(f"Admin account created successfully for {email}!")
    except sqlite3.IntegrityError:
        print(f"Error: An account with email {email} already exists.")
    finally:
        c.close()

elif choice in ('2', 'complaint_team', 'ct'):
    name = input("Complaint Team member name: ").strip()
    phone = input("Phone (internal): ").strip()
    password = input("Password (min 6 chars): ").strip()
    if not name or len(password) < 6:
        c.close()
        raise SystemExit("Name and password (min 6 chars) are required.")
    
    row = c.execute("SELECT member_id FROM users WHERE role='complaint_team' AND member_id IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    try:
        n = int(row[0][2:]) + 1 if row and row[0] and row[0].startswith('CT') else 1
    except (ValueError, TypeError, IndexError):
        n = 1
    member_id = f'CT{n:03d}'
    email = f'{member_id.lower()}@internal.loopify'
    try:
        c.execute("INSERT INTO users(name,email,phone,password_hash,role,member_id) VALUES(?,?,?,?,?,?)",
                  (name, email, phone, generate_password_hash(password), 'complaint_team', member_id))
        c.commit()
        print(f"Complaint Team member created: {member_id} (Login using Member ID '{member_id}')")
    except sqlite3.IntegrityError as e:
        print(f"Error creating member: {e}")
    finally:
        c.close()
else:
    c.close()
    print("Invalid option selected.")

