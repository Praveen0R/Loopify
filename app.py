from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, uuid, re
from pathlib import Path
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-before-production')
BASE = Path(__file__).resolve().parent
DB = BASE / 'loopify.db'
UPLOADS = BASE / 'static' / 'uploads'
UPLOADS.mkdir(parents=True, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
ALLOWED = {'png','jpg','jpeg','webp'}
# Keep this list college-appropriate and extend it for your campus language policy.
BAD_WORDS = {'spamword1','spamword2','badword'}


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c


def init_db():
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, member_id TEXT UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
      department TEXT, semester INTEGER, public_key TEXT,
      blocked_until TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS products(
      id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
      title TEXT NOT NULL, category TEXT NOT NULL, description TEXT,
      department TEXT, semester INTEGER, subject TEXT, subject_code TEXT,
      listing_type TEXT NOT NULL DEFAULT 'SELL', price INTEGER NOT NULL,
      exchange_for TEXT, condition TEXT NOT NULL, quantity INTEGER NOT NULL DEFAULT 1,
      sold_count INTEGER NOT NULL DEFAULT 0, photo TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS ratings(
      id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL, rater_id INTEGER NOT NULL,
      rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), review TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(product_id,rater_id),
      FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
      FOREIGN KEY(rater_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS blocks(
      id INTEGER PRIMARY KEY AUTOINCREMENT, blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(blocker_id,blocked_id),
      FOREIGN KEY(blocker_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(blocked_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS conversations(
      id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL,
      buyer_id INTEGER NOT NULL, seller_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(product_id,buyer_id,seller_id),
      FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
      FOREIGN KEY(buyer_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL, ciphertext TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
      FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS complaints(
      id INTEGER PRIMARY KEY AUTOINCREMENT, raiser_id INTEGER NOT NULL, accused_id INTEGER NOT NULL,
      product_id INTEGER, category TEXT NOT NULL, description TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'OPEN', resolution TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, resolved_at TIMESTAMP,
      FOREIGN KEY(raiser_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(accused_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_products_subject_code ON products(subject_code);
    CREATE INDEX IF NOT EXISTS idx_products_department_semester ON products(department,semester);
    CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);
    CREATE TABLE IF NOT EXISTS call_sessions(
      id INTEGER PRIMARY KEY AUTOINCREMENT, room_key TEXT NOT NULL UNIQUE,
      caller_id INTEGER NOT NULL, callee_id INTEGER NOT NULL,
      offer TEXT, answer TEXT, caller_candidates TEXT DEFAULT '[]', callee_candidates TEXT DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'RINGING', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(caller_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(callee_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS reservations(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      buyer_id INTEGER NOT NULL,
      seller_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'PENDING',
      buyer_note TEXT,
      seller_note TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      responded_at TIMESTAMP,
      completed_at TIMESTAMP,
      FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
      FOREIGN KEY(buyer_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_reservations_seller_status ON reservations(seller_id,status);
    CREATE INDEX IF NOT EXISTS idx_reservations_buyer_status ON reservations(buyer_id,status);
    CREATE INDEX IF NOT EXISTS idx_reservations_product_status ON reservations(product_id,status);
    ''')
    cols = {r['name'] for r in c.execute('PRAGMA table_info(users)').fetchall()}
    if 'member_id' not in cols:
        c.execute('ALTER TABLE users ADD COLUMN member_id TEXT')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_member_id ON users(member_id)')
    c.commit(); c.close()


def current_user():
    if 'user_id' not in session: return None
    c=db(); u=c.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone(); c.close(); return u


def has_bad_words(text):
    low = re.sub(r'[^a-zA-Z0-9 ]',' ', text.lower())
    return any(re.search(rf'\b{re.escape(w)}\b', low) for w in BAD_WORDS)


def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if 'user_id' not in session:
            flash('Please login first.','error'); return redirect(url_for('login'))
        return f(*a,**k)
    return w


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a,**k):
            if 'user_id' not in session: return redirect(url_for('login'))
            if session.get('role') not in roles: abort(403)
            return f(*a,**k)
        return w
    return deco


@app.context_processor
def inject():
    return {'current_user': current_user()}


def allowed_file(n): return '.' in n and n.rsplit('.',1)[1].lower() in ALLOWED


def blocked_between(c, a, b):
    return c.execute('SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=? OR blocker_id=? AND blocked_id=?',(a,b,b,a)).fetchone() is not None


@app.route('/')
def index():
    q=request.args.get('q','').strip(); dep=request.args.get('department','').strip(); sem=request.args.get('semester','').strip(); code=request.args.get('subject_code','').strip(); cat=request.args.get('category','').strip()
    c=db()
    sql='''SELECT p.*,u.name owner_name,COALESCE(AVG(r.rating),0) avg_rating,COUNT(r.id) rating_count
           FROM products p JOIN users u ON u.id=p.owner_id LEFT JOIN ratings r ON r.product_id=p.id WHERE 1=1'''; par=[]
    if q:
        x=f'%{q.lower()}%'
        sql += " AND (LOWER(COALESCE(p.title,'')) LIKE ? OR LOWER(COALESCE(p.description,'')) LIKE ? OR LOWER(COALESCE(p.subject,'')) LIKE ? OR LOWER(COALESCE(p.subject_code,'')) LIKE ? OR LOWER(COALESCE(p.department,'')) LIKE ? OR LOWER(COALESCE(p.category,'')) LIKE ?)"
        par += [x,x,x,x,x,x]
    if dep:
        sql += " AND LOWER(COALESCE(p.department,'')) = LOWER(?)"
        par.append(dep.strip())
    if sem:
        try:
            sql+=' AND p.semester=?'
            par.append(int(sem))
        except ValueError:
            pass
    if code:
        sql += " AND LOWER(COALESCE(p.subject_code,'')) LIKE ?"
        par.append(f'%{code.lower()}%')
    if cat:
        sql += " AND LOWER(COALESCE(p.category,'')) = LOWER(?)"
        par.append(cat.strip())
    sql+=' GROUP BY p.id ORDER BY CASE WHEN p.price=0 THEN 0 ELSE 1 END, p.created_at DESC'
    products=c.execute(sql,par).fetchall()
    categories=[r['category'] for r in c.execute('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category').fetchall()]
    departments=[r['department'] for r in c.execute("SELECT DISTINCT department FROM products WHERE department IS NOT NULL AND department!='' ORDER BY department").fetchall()]
    free_products=[p for p in products if p['price']==0 and p['quantity']>0]
    recent_products=products[:6]
    recommended_products=[]
    user=current_user()
    if user and (user['department'] or user['semester']):
        rec_sql='''SELECT p.*,u.name owner_name,COALESCE(AVG(r.rating),0) avg_rating,COUNT(r.id) rating_count
                    FROM products p JOIN users u ON u.id=p.owner_id LEFT JOIN ratings r ON r.product_id=p.id
                    WHERE p.quantity>0 AND p.owner_id!=? AND p.id NOT IN (SELECT id FROM products WHERE owner_id=? )'''
        rec_params=[user['id'],user['id']]
        if user['department']:
            rec_sql += " AND LOWER(COALESCE(p.department,'')) = LOWER(?)"
            rec_params.append(user['department'])
        if user['semester']:
            rec_sql+=' AND p.semester=?'
            rec_params.append(user['semester'])
        rec_sql+=' GROUP BY p.id ORDER BY p.created_at DESC LIMIT 6'
        recommended_products=c.execute(rec_sql,rec_params).fetchall()
    c.close(); return render_template('index.html',products=products,recent_products=recent_products,free_products=free_products[:6],recommended_products=recommended_products,categories=categories,departments=departments,q=q,selected_department=dep,selected_semester=sem,subject_code=code,selected_category=cat)


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        name=request.form['name'].strip(); email=request.form['email'].strip().lower(); phone=request.form['phone'].strip(); pw=request.form['password']; dep=request.form.get('department','').strip(); sem=request.form.get('semester') or None
        try: sem=int(sem) if sem else None
        except ValueError: sem=None
        if has_bad_words(name): flash('Please use appropriate language in your name.','error'); return redirect(url_for('register'))
        if not all([name,email,phone]) or len(pw)<6: flash('Fill all fields. Password must be at least 6 characters.','error'); return redirect(url_for('register'))
        c=db()
        try:
            c.execute('INSERT INTO users(name,email,phone,password_hash,department,semester) VALUES(?,?,?,?,?,?)',(name,email,phone,generate_password_hash(pw),dep,sem)); c.commit()
        except sqlite3.IntegrityError:
            c.close(); flash('That email is already registered.','error'); return redirect(url_for('register'))
        c.close(); flash('Account created. Please login.','success'); return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        identifier=request.form['identifier'].strip(); pw=request.form['password']; c=db(); u=c.execute('SELECT * FROM users WHERE lower(email)=lower(?) OR member_id=?',(identifier,identifier)).fetchone(); c.close()
        if u and check_password_hash(u['password_hash'],pw):
            session.clear(); session['user_id']=u['id']; session['role']=u['role']; session['name']=u['name']; flash('Welcome back!','success'); return redirect(url_for('index'))
        flash('Invalid ID/email or password.','error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('index'))


@app.route('/sell',methods=['GET','POST'])
@login_required
def sell():
    if request.method=='POST':
        f=request.form; title=f['title'].strip(); desc=f.get('description','').strip(); subject=f.get('subject','').strip(); subject_code=f.get('subject_code','').strip(); exchange=f.get('exchange_for','').strip()
        if any(has_bad_words(x) for x in [title,desc,subject,exchange]): flash('Please remove inappropriate language from your listing.','error'); return redirect(url_for('sell'))
        try: price=int(f.get('price','0')); qty=int(f.get('quantity','1')); sem=int(f['semester']) if f.get('semester') else None
        except ValueError: flash('Price, semester and quantity must be valid numbers.','error'); return redirect(url_for('sell'))
        if price<0 or qty<1: flash('Invalid price/quantity.','error'); return redirect(url_for('sell'))
        photo=request.files.get('photo')
        if not photo or not photo.filename or not allowed_file(photo.filename): flash('Upload PNG/JPG/JPEG/WEBP photo.','error'); return redirect(url_for('sell'))
        ext=photo.filename.rsplit('.',1)[1].lower(); photo_name=f'{uuid.uuid4().hex}.{ext}'; photo.save(UPLOADS/secure_filename(photo_name))
        c=db(); c.execute('''INSERT INTO products(owner_id,title,category,description,department,semester,subject,subject_code,listing_type,price,exchange_for,condition,quantity,photo)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(session['user_id'],title,f['category'],desc,f.get('department','').strip(),sem,subject,subject_code,f.get('listing_type','SELL'),price,exchange,f.get('condition','Used'),qty,photo_name)); c.commit(); c.close()
        flash('Product listed successfully!','success'); return redirect(url_for('index'))
    return render_template('sell.html')


@app.route('/product/<int:pid>')
def product(pid):
    c=db(); p=c.execute('''SELECT p.*,u.name owner_name,u.phone owner_phone,u.id owner_id,u.public_key owner_public_key,COALESCE(AVG(r.rating),0) avg_rating,COUNT(r.id) rating_count
                           FROM products p JOIN users u ON u.id=p.owner_id LEFT JOIN ratings r ON r.product_id=p.id WHERE p.id=? GROUP BY p.id''',(pid,)).fetchone()
    if not p: c.close(); abort(404)
    conds = []
    pars = [pid]
    if p['title'] and p['title'].strip():
        conds.append("LOWER(COALESCE(p.title,'')) LIKE LOWER(?)")
        pars.append(f"%{p['title'].strip().lower()}%")
    if p['subject'] and p['subject'].strip():
        conds.append("LOWER(COALESCE(p.subject,'')) LIKE LOWER(?)")
        pars.append(f"%{p['subject'].strip().lower()}%")
    if p['subject_code'] and p['subject_code'].strip():
        conds.append("LOWER(COALESCE(p.subject_code,'')) LIKE LOWER(?)")
        pars.append(f"%{p['subject_code'].strip().lower()}%")
    if p['category'] and p['category'].strip():
        conds.append("LOWER(COALESCE(p.category,'')) = LOWER(?)")
        pars.append(p['category'].strip().lower())

    same = []
    if conds:
        where_clause = " OR ".join(conds)
        same_sql = f'''SELECT p.*,u.name owner_name,COALESCE(AVG(r.rating),0) avg_rating,COUNT(r.id) rating_count
                       FROM products p JOIN users u ON u.id=p.owner_id LEFT JOIN ratings r ON r.product_id=p.id
                       WHERE p.id!=? AND p.quantity>0 AND ({where_clause})
                       GROUP BY p.id ORDER BY p.created_at DESC LIMIT 6'''
        same = c.execute(same_sql, pars).fetchall()
    reviews=c.execute('SELECT r.*,u.name FROM ratings r JOIN users u ON u.id=r.rater_id WHERE r.product_id=? ORDER BY r.created_at DESC',(pid,)).fetchall()
    my_reservation=None
    if 'user_id' in session:
        my_reservation=c.execute("SELECT * FROM reservations WHERE product_id=? AND buyer_id=? ORDER BY id DESC LIMIT 1",(pid,session['user_id'])).fetchone()
    c.close()
    return render_template('detail.html',product=p,same_items=same,reviews=reviews,my_reservation=my_reservation)


@app.route('/product/<int:pid>/reserve', methods=['POST'])
@login_required
def request_reservation(pid):
    """Create a pending request. Stock is unchanged until seller accepts."""
    c = db()
    p = c.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
    if not p:
        c.close(); abort(404)
    if p['owner_id'] == session['user_id']:
        c.close(); flash('You cannot reserve your own product.', 'error'); return redirect(url_for('product', pid=pid))
    if p['quantity'] < 1:
        c.close(); flash('This product is out of stock.', 'error'); return redirect(url_for('product', pid=pid))
    if blocked_between(c, session['user_id'], p['owner_id']):
        c.close(); flash('This user interaction is blocked.', 'error'); return redirect(url_for('product', pid=pid))

    existing = c.execute(
        "SELECT 1 FROM reservations WHERE product_id=? AND buyer_id=? AND seller_id=? AND status='PENDING' LIMIT 1",
        (pid, session['user_id'], p['owner_id'])
    ).fetchone()
    if existing:
        c.close(); flash('You already sent a reservation request for this product.', 'error'); return redirect(url_for('product', pid=pid))

    c.execute(
        'INSERT INTO reservations(product_id,buyer_id,seller_id,quantity,status) VALUES(?,?,?,?,?)',
        (pid, session['user_id'], p['owner_id'], 1, 'PENDING')
    )
    c.commit(); c.close()
    flash('Reservation request sent to the seller.', 'success')
    return redirect(url_for('product', pid=pid))


@app.route('/product/<int:pid>/buy', methods=['POST'])
@login_required
def buy_compatibility(pid):
    return request_reservation(pid)


@app.route('/reservations')
@login_required
def reservations():
    c=db()
    buyer=c.execute("""SELECT r.*,p.title,p.photo,u.name seller_name FROM reservations r
                     JOIN products p ON p.id=r.product_id JOIN users u ON u.id=r.seller_id
                     WHERE r.buyer_id=? ORDER BY r.created_at DESC""",(session['user_id'],)).fetchall()
    seller=c.execute("""SELECT r.*,p.title,p.photo,u.name buyer_name FROM reservations r
                      JOIN products p ON p.id=r.product_id JOIN users u ON u.id=r.buyer_id
                      WHERE r.seller_id=? ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END,r.created_at DESC""",(session['user_id'],)).fetchall()
    c.close(); return render_template('reservations.html',buyer_reservations=buyer,seller_reservations=seller)


@app.route('/reservation/<int:rid>/accept', methods=['POST'])
@login_required
def accept_reservation(rid):
    c=db(); c.execute('BEGIN IMMEDIATE')
    r=c.execute('SELECT * FROM reservations WHERE id=?',(rid,)).fetchone()
    if not r or r['seller_id']!=session['user_id']:
        c.rollback(); c.close(); abort(403)
    if r['status']!='PENDING':
        c.rollback(); c.close(); flash('This reservation is no longer pending.','error'); return redirect(url_for('reservations'))
    p=c.execute('SELECT * FROM products WHERE id=?',(r['product_id'],)).fetchone()
    if not p or p['quantity']<r['quantity']:
        c.rollback(); c.close(); flash('Not enough stock is available to accept this request.','error'); return redirect(url_for('reservations'))
    note=request.form.get('seller_note','').strip()
    if has_bad_words(note):
        c.rollback(); c.close(); flash('Please remove inappropriate language from the seller note.','error'); return redirect(url_for('reservations'))
    # Stock changes ONLY when the seller accepts.
    c.execute('UPDATE products SET quantity=quantity-? WHERE id=?',(r['quantity'],r['product_id']))
    c.execute("UPDATE reservations SET status='ACCEPTED',seller_note=?,responded_at=CURRENT_TIMESTAMP WHERE id=?",(note,rid))
    remaining=c.execute('SELECT quantity FROM products WHERE id=?',(r['product_id'],)).fetchone()['quantity']
    if remaining < 1:
        c.execute("UPDATE reservations SET status='REJECTED',seller_note='Another reservation used the remaining stock.',responded_at=CURRENT_TIMESTAMP WHERE product_id=? AND status='PENDING' AND id<>?",(r['product_id'],rid))
    c.commit(); c.close()
    flash('Reservation accepted. The requested quantity is now reserved and unavailable.','success')
    return redirect(url_for('reservations'))


@app.route('/reservation/<int:rid>/reject', methods=['POST'])
@login_required
def reject_reservation(rid):
    c=db(); r=c.execute('SELECT * FROM reservations WHERE id=?',(rid,)).fetchone()
    if not r or r['seller_id']!=session['user_id']:
        c.close(); abort(403)
    if r['status']!='PENDING':
        c.close(); flash('This reservation is no longer pending.','error'); return redirect(url_for('reservations'))
    note=request.form.get('seller_note','').strip()
    if has_bad_words(note):
        c.close(); flash('Please remove inappropriate language from the seller note.','error'); return redirect(url_for('reservations'))
    c.execute("UPDATE reservations SET status='REJECTED',seller_note=?,responded_at=CURRENT_TIMESTAMP WHERE id=?",(note,rid)); c.commit(); c.close()
    flash('Reservation rejected. The product remains available.','success')
    return redirect(url_for('reservations'))


@app.route('/reservation/<int:rid>/complete', methods=['POST'])
@login_required
def complete_reservation(rid):
    c=db(); r=c.execute('SELECT * FROM reservations WHERE id=?',(rid,)).fetchone()
    if not r or r['seller_id']!=session['user_id']:
        c.close(); abort(403)
    if r['status']!='ACCEPTED':
        c.close(); flash('Only accepted reservations can be completed.','error'); return redirect(url_for('reservations'))
    c.execute("UPDATE reservations SET status='COMPLETED',completed_at=CURRENT_TIMESTAMP WHERE id=?",(rid,)); c.execute('UPDATE products SET sold_count=sold_count+? WHERE id=?',(r['quantity'],r['product_id']))
    c.commit(); c.close(); flash('Sale completed. Buyer can now rate the product.','success'); return redirect(url_for('reservations'))


@app.route('/product/<int:pid>/rate',methods=['POST'])
@login_required
def rate(pid):
    try: rating=int(request.form['rating'])
    except: rating=0
    review=request.form.get('review','').strip()
    if has_bad_words(review): flash('Please remove inappropriate language from the review.','error'); return redirect(url_for('product',pid=pid))
    c=db(); p=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
    if not p: c.close(); abort(404)
    if p['owner_id']==session['user_id']: c.close(); flash('You cannot rate your own product.','error'); return redirect(url_for('product',pid=pid))
    completed=c.execute("SELECT 1 FROM reservations WHERE product_id=? AND buyer_id=? AND status='COMPLETED' LIMIT 1",(pid,session['user_id'])).fetchone()
    if not completed: c.close(); flash('You can rate this product only after a completed sale.','error'); return redirect(url_for('product',pid=pid))
    if rating not in range(1,6): c.close(); flash('Rating must be 1-5.','error'); return redirect(url_for('product',pid=pid))
    c.execute("INSERT INTO ratings(product_id,rater_id,rating,review) VALUES(?,?,?,?) ON CONFLICT(product_id,rater_id) DO UPDATE SET rating=excluded.rating,review=excluded.review,created_at=CURRENT_TIMESTAMP",(pid,session['user_id'],rating,review)); c.commit(); c.close(); flash('Rating saved.','success'); return redirect(url_for('product',pid=pid))


@app.route('/user/<int:uid>')
def profile(uid):
    c=db()
    u=c.execute('SELECT u.id,u.name,u.department,u.semester,u.created_at,COALESCE(AVG(r.rating),0) avg_rating,COUNT(r.id) rating_count FROM users u LEFT JOIN products p ON p.owner_id=u.id LEFT JOIN ratings r ON r.product_id=p.id WHERE u.id=? GROUP BY u.id',(uid,)).fetchone()
    if not u:
        c.close(); abort(404)
    p=c.execute('SELECT * FROM products WHERE owner_id=? ORDER BY created_at DESC',(uid,)).fetchall()
    is_blocked = False
    if 'user_id' in session:
        is_blocked = c.execute('SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?',(session['user_id'],uid)).fetchone() is not None
    c.close()
    return render_template('profile.html',user=u,products=p,is_blocked=is_blocked)


@app.route('/user/<int:uid>/edit', methods=['GET','POST'])
@login_required
def edit_profile(uid):
    if uid != session['user_id']:
        abort(403)
    c=db(); u=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone();
    if not u:
        c.close(); abort(404)
    if request.method=='POST':
        name=request.form.get('name','').strip()
        phone=request.form.get('phone','').strip()
        department=request.form.get('department','').strip()
        semester=request.form.get('semester','').strip()
        if has_bad_words(name):
            c.close(); flash('Please use appropriate language in your profile name.','error'); return redirect(url_for('edit_profile',uid=uid))
        try:
            semester=int(semester) if semester else None
        except ValueError:
            c.close(); flash('Semester must be a valid number.','error'); return redirect(url_for('edit_profile',uid=uid))
        if not name or not phone:
            c.close(); flash('Name and phone number are required.','error'); return redirect(url_for('edit_profile',uid=uid))
        c.execute('UPDATE users SET name=?, phone=?, department=?, semester=? WHERE id=?',(name,phone,department or None,semester,uid)); c.commit(); c.close();
        session['name']=name
        flash('Profile updated successfully.','success'); return redirect(url_for('profile',uid=uid))
    c.close(); return render_template('edit_profile.html',user=u)


@app.route('/my-listings')
@login_required
def my_listings():
    c=db()
    p=c.execute('SELECT p.*,COALESCE(AVG(r.rating),0) avg_rating,COUNT(r.id) rating_count FROM products p LEFT JOIN ratings r ON r.product_id=p.id WHERE p.owner_id=? GROUP BY p.id ORDER BY p.created_at DESC',(session['user_id'],)).fetchall()
    incoming=c.execute("""SELECT r.*,p.title,p.photo,u.name buyer_name FROM reservations r
                       JOIN products p ON p.id=r.product_id JOIN users u ON u.id=r.buyer_id
                       WHERE r.seller_id=? ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END,r.created_at DESC""",(session['user_id'],)).fetchall()
    c.close(); return render_template('my_listings.html',products=p,incoming_reservations=incoming)


@app.route('/product/<int:pid>/delete', methods=['POST'])
@login_required
def delete_product(pid):
    c=db(); p=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
    if not p:
        c.close(); abort(404)
    if p['owner_id'] != session['user_id'] and session.get('role') != 'admin':
        c.close(); abort(403)
    if p['photo']:
        try:
            (UPLOADS / p['photo']).unlink(missing_ok=True)
        except Exception:
            pass
    c.execute('DELETE FROM products WHERE id=?',(pid,)); c.commit(); c.close();
    ref = request.referrer or ''
    target = url_for('my_listings') if f'/product/{pid}' in ref else (ref or url_for('my_listings'))
    flash('Product deleted successfully.','success'); return redirect(target)


@app.route('/product/<int:pid>/mark-sold', methods=['POST'])
@login_required
def mark_product_sold(pid):
    c=db(); p=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
    if not p:
        c.close(); abort(404)
    if p['owner_id'] != session['user_id']:
        c.close(); abort(403)
    if p['quantity'] <= 0:
        c.close(); flash('This product is already marked sold.','error'); return redirect(request.referrer or url_for('my_listings'))
    c.execute('UPDATE products SET quantity=0, sold_count=sold_count+1 WHERE id=?',(pid,)); c.commit(); c.close();
    flash('Product marked sold.','success'); return redirect(request.referrer or url_for('my_listings'))


@app.route('/user/<int:uid>/block',methods=['POST'])
@login_required
def block_user(uid):
    if uid==session['user_id']: flash('You cannot block yourself.','error'); return redirect(url_for('profile',uid=uid))
    c=db(); c.execute('INSERT OR IGNORE INTO blocks(blocker_id,blocked_id) VALUES(?,?)',(session['user_id'],uid)); c.commit(); c.close(); flash('User blocked. Chat and purchase interactions with this account are disabled.','success'); return redirect(request.referrer or url_for('index'))


@app.route('/user/<int:uid>/unblock',methods=['POST'])
@login_required
def unblock_user(uid):
    c=db(); c.execute('DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?',(session['user_id'],uid)); c.commit(); c.close(); flash('User unblocked.','success'); return redirect(request.referrer or url_for('index'))


@app.route('/complaint/new',methods=['GET','POST'])
@login_required
def new_complaint():
    accused=request.args.get('accused_id',type=int)
    product_id=request.args.get('product_id',type=int)
    
    if request.method=='POST':
        try:
            accused=int(request.form.get('accused_id') or 0)
        except (ValueError, TypeError):
            accused=0
        try:
            p_val=request.form.get('product_id')
            product_id=int(p_val) if p_val else None
        except (ValueError, TypeError):
            product_id=None
            
        category=request.form.get('category','OTHER')
        desc=request.form.get('description','').strip()
        
        if not desc:
            flash('Please enter details of your complaint.','error')
            return redirect(url_for('new_complaint',accused_id=accused,product_id=product_id))
        if has_bad_words(desc):
            flash('Please use appropriate language in the complaint.','error')
            return redirect(url_for('new_complaint',accused_id=accused,product_id=product_id))
            
        c=db()
        exists=c.execute('SELECT 1 FROM users WHERE id=?',(accused,)).fetchone()
        if not exists or accused==session['user_id']:
            c.close()
            flash('Invalid complaint target. Please report a valid user.','error')
            return redirect(url_for('index'))
            
        c.execute('INSERT INTO complaints(raiser_id,accused_id,product_id,category,description) VALUES(?,?,?,?,?)',
                  (session['user_id'],accused,product_id,category,desc))
        c.commit()
        c.close()
        flash('Complaint submitted to the Complaint Management Team.','success')
        return redirect(url_for('index'))

    c=db()
    accused_user=c.execute('SELECT id, name, department FROM users WHERE id=?',(accused,)).fetchone() if accused else None
    product=c.execute('SELECT id, title FROM products WHERE id=?',(product_id,)).fetchone() if product_id else None
    c.close()
    
    return render_template('complaint_form.html',accused_id=accused,product_id=product_id,accused_user=accused_user,product=product)


@app.route('/complaints')
@role_required('complaint_team','admin')
def complaints():
    c=db(); rows=c.execute('''SELECT co.*, r.name raiser_name,r.email raiser_email,r.phone raiser_phone,r.department raiser_department,
                              a.name accused_name,a.email accused_email,a.phone accused_phone,a.department accused_department,
                              p.title product_title FROM complaints co JOIN users r ON r.id=co.raiser_id JOIN users a ON a.id=co.accused_id
                              LEFT JOIN products p ON p.id=co.product_id ORDER BY CASE co.status WHEN 'OPEN' THEN 0 ELSE 1 END,co.created_at DESC''').fetchall(); c.close(); return render_template('complaints.html',complaints=rows)


@app.route('/complaints/<int:cid>/resolve',methods=['POST'])
@role_required('complaint_team','admin')
def resolve_complaint(cid):
    resolution=request.form.get('resolution','').strip()
    if has_bad_words(resolution): flash('Please use appropriate language.','error'); return redirect(url_for('complaints'))
    c=db(); c.execute("UPDATE complaints SET status='RESOLVED',resolution=?,resolved_at=CURRENT_TIMESTAMP WHERE id=?",(resolution,cid)); c.commit(); c.close(); flash('Complaint marked resolved.','success'); return redirect(url_for('complaints'))


@app.route('/chats')
@login_required
def chats():
    c=db()
    rows=c.execute('''SELECT c.id,c.product_id,c.buyer_id,c.seller_id,c.created_at,p.title,
                            CASE WHEN c.buyer_id=? THEN s.id ELSE b.id END other_id,
                            CASE WHEN c.buyer_id=? THEN s.name ELSE b.name END other_name,
                            (SELECT m.created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) last_message_at
                     FROM conversations c
                     JOIN products p ON p.id=c.product_id
                     JOIN users b ON b.id=c.buyer_id
                     JOIN users s ON s.id=c.seller_id
                     WHERE c.buyer_id=? OR c.seller_id=?
                     ORDER BY COALESCE(last_message_at,c.created_at) DESC''',
                  (session['user_id'],session['user_id'],session['user_id'],session['user_id'])).fetchall()
    c.close()
    return render_template('chats.html', conversations=rows)

@app.route('/chat/start/<int:pid>',methods=['POST'])
@login_required
def chat_start(pid):
    c=db(); p=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
    if not p: c.close(); abort(404)
    if p['owner_id']==session['user_id']: c.close(); flash('You are the owner.','error'); return redirect(url_for('product',pid=pid))
    if blocked_between(c,session['user_id'],p['owner_id']): c.close(); flash('Chat is blocked between these accounts.','error'); return redirect(url_for('product',pid=pid))
    c.execute('INSERT INTO conversations(product_id,buyer_id,seller_id) VALUES(?,?,?) ON CONFLICT(product_id,buyer_id,seller_id) DO NOTHING',(pid,session['user_id'],p['owner_id'])); c.commit(); x=c.execute('SELECT id FROM conversations WHERE product_id=? AND buyer_id=? AND seller_id=?',(pid,session['user_id'],p['owner_id'])).fetchone(); c.close(); return redirect(url_for('chat',cid=x['id']))


@app.route('/chat/<int:cid>', methods=['GET','POST'])
@login_required
def chat(cid):
    c=db(); con=c.execute('''SELECT c.*,p.title,b.name buyer_name,s.name seller_name
                             FROM conversations c JOIN products p ON p.id=c.product_id JOIN users b ON b.id=c.buyer_id JOIN users s ON s.id=c.seller_id WHERE c.id=?''',(cid,)).fetchone()
    if not con or session['user_id'] not in (con['buyer_id'],con['seller_id']): c.close(); abort(403)
    if blocked_between(c,con['buyer_id'],con['seller_id']): c.close(); abort(403)
    
    if request.method == 'POST':
        msg = request.form.get('message','').strip()
        if msg:
            if has_bad_words(msg):
                flash('Please remove inappropriate language from your message.','error')
            else:
                c.execute('INSERT INTO messages(conversation_id,sender_id,ciphertext) VALUES(?,?,?)',(cid,session['user_id'],msg))
                c.commit()
        c.close()
        return redirect(url_for('chat', cid=cid))

    msgs=c.execute('SELECT * FROM messages WHERE conversation_id=? ORDER BY id',(cid,)).fetchall(); c.close()
    oid=con['seller_id'] if session['user_id']==con['buyer_id'] else con['buyer_id']
    oname=con['seller_name'] if session['user_id']==con['buyer_id'] else con['buyer_name']
    return render_template('chat.html',conversation=con,messages=msgs,other_id=oid,other_name=oname)


@app.route('/api/public-key',methods=['POST'])
@login_required
def save_pk():
    pk=(request.json or {}).get('public_key','');
    if not pk:return jsonify(error='Missing key'),400
    c=db(); c.execute('UPDATE users SET public_key=? WHERE id=?',(pk,session['user_id'])); c.commit(); c.close(); return jsonify(ok=True)


@app.route('/api/chat-key/<int:uid>')
@login_required
def get_chat_key(uid):
    c=db()
    allowed=c.execute('''SELECT 1 FROM conversations
                         WHERE (buyer_id=? AND seller_id=?)
                            OR (buyer_id=? AND seller_id=?)
                         LIMIT 1''',(session['user_id'],uid,uid,session['user_id'])).fetchone()
    user=c.execute('SELECT public_key FROM users WHERE id=?',(uid,)).fetchone() if allowed else None
    c.close()
    if not user:return jsonify(error='Forbidden'),403
    return jsonify(public_key=user['public_key'] or '')


@app.route('/api/messages/<int:cid>',methods=['POST'])
@login_required
def send_message(cid):
    data = request.get_json(silent=True) or request.form
    text = (data.get('text') or data.get('message') or data.get('ciphertext') or '').strip()
    if not text:
        return jsonify(error='Message cannot be empty'), 400
    if has_bad_words(text):
        return jsonify(error='Please keep messages respectful and free of prohibited words.'), 400
    c=db(); con=c.execute('SELECT buyer_id,seller_id FROM conversations WHERE id=?',(cid,)).fetchone()
    if not con or session['user_id'] not in (con['buyer_id'],con['seller_id']) or blocked_between(c,con['buyer_id'],con['seller_id']):
        c.close(); return jsonify(error='Forbidden'), 403
    c.execute('INSERT INTO messages(conversation_id,sender_id,ciphertext) VALUES(?,?,?)',(cid,session['user_id'],text))
    c.commit(); c.close(); return jsonify(ok=True)


@app.route('/api/messages/<int:cid>')
@login_required
def get_messages(cid):
    c=db(); con=c.execute('SELECT buyer_id,seller_id FROM conversations WHERE id=?',(cid,)).fetchone()
    if not con or session['user_id'] not in (con['buyer_id'],con['seller_id']) or blocked_between(c,con['buyer_id'],con['seller_id']):
        c.close(); return jsonify(error='Forbidden'), 403
    rows=c.execute('''SELECT m.id, m.sender_id, m.ciphertext, m.created_at, u.name as sender_name
                      FROM messages m
                      JOIN users u ON u.id = m.sender_id
                      WHERE m.conversation_id=?
                      ORDER BY m.id ASC''',(cid,)).fetchall()
    c.close()
    out = []
    for r in rows:
        out.append({
            'id': r['id'],
            'sender_id': r['sender_id'],
            'sender_name': r['sender_name'],
            'text': r['ciphertext'],
            'ciphertext': r['ciphertext'],
            'created_at': r['created_at']
        })
    return jsonify(out)


@app.route('/api/messages/<int:cid>/<int:mid>',methods=['DELETE'])
@login_required
def delete_message(cid,mid):
    c=db(); con=c.execute('SELECT buyer_id,seller_id FROM conversations WHERE id=?',(cid,)).fetchone()
    if not con or session['user_id'] not in (con['buyer_id'],con['seller_id']) or blocked_between(c,con['buyer_id'],con['seller_id']): c.close(); return jsonify(error='Forbidden'),403
    msg=c.execute('SELECT id,sender_id FROM messages WHERE id=? AND conversation_id=?',(mid,cid)).fetchone()
    if not msg: c.close(); return jsonify(error='Message not found'),404
    if msg['sender_id'] != session['user_id']: c.close(); return jsonify(error='Forbidden'),403
    c.execute('DELETE FROM messages WHERE id=? AND conversation_id=?',(mid,cid)); c.commit(); c.close(); return jsonify(ok=True)


@app.route('/call/<int:uid>')
@login_required
def call_page(uid):
    if uid == session['user_id']: abort(400)
    c=db(); other=c.execute('SELECT id,name FROM users WHERE id=?',(uid,)).fetchone()
    if not other or blocked_between(c,session['user_id'],uid): c.close(); abort(403)
    room='-'.join(map(str,sorted([session['user_id'],uid])))
    c.execute("""INSERT INTO call_sessions(room_key,caller_id,callee_id,offer,answer,caller_candidates,callee_candidates,status)
                 VALUES(?,?,?,NULL,NULL,'[]','[]','RINGING')
                 ON CONFLICT(room_key) DO UPDATE SET
                     caller_id=excluded.caller_id,
                     callee_id=excluded.callee_id,
                     offer=NULL,
                     answer=NULL,
                     caller_candidates='[]',
                     callee_candidates='[]',
                     status='RINGING',
                     created_at=CURRENT_TIMESTAMP""",(room,session['user_id'],uid))
    c.commit(); c.close()
    return render_template('call.html',other_id=uid,other_name=other['name'],room_key=room)

@app.route('/api/call/<room>/state')
@login_required
def call_state(room):
    import json
    c=db(); row=c.execute('SELECT * FROM call_sessions WHERE room_key=?',(room,)).fetchone()
    if not row or session['user_id'] not in (row['caller_id'],row['callee_id']): c.close(); return jsonify(error='Forbidden'),403
    out={'caller_id':row['caller_id'],'callee_id':row['callee_id'],'offer':row['offer'],'answer':row['answer'],'status':row['status'],'mine_is_caller':session['user_id']==row['caller_id']}
    out['other_candidates']=json.loads(row['callee_candidates'] if session['user_id']==row['caller_id'] else row['caller_candidates'])
    c.close(); return jsonify(out)

@app.route('/api/call/<room>/offer',methods=['POST'])
@login_required
def call_offer(room):
    offer=(request.json or {}).get('offer')
    c=db(); row=c.execute('SELECT * FROM call_sessions WHERE room_key=?',(room,)).fetchone()
    if not offer or not row or session['user_id']!=row['caller_id']: c.close(); return jsonify(error='Forbidden'),403
    c.execute("UPDATE call_sessions SET offer=?,status='OFFERED' WHERE room_key=?",(offer,room)); c.commit(); c.close(); return jsonify(ok=True)

@app.route('/api/call/<room>/answer',methods=['POST'])
@login_required
def call_answer(room):
    answer=(request.json or {}).get('answer')
    c=db(); row=c.execute('SELECT * FROM call_sessions WHERE room_key=?',(room,)).fetchone()
    if not answer or not row or session['user_id']!=row['callee_id']: c.close(); return jsonify(error='Forbidden'),403
    c.execute("UPDATE call_sessions SET answer=?,status='CONNECTED' WHERE room_key=?",(answer,room)); c.commit(); c.close(); return jsonify(ok=True)

@app.route('/api/call/<room>/candidate',methods=['POST'])
@login_required
def call_candidate(room):
    import json
    cand=(request.json or {}).get('candidate')
    c=db(); row=c.execute('SELECT * FROM call_sessions WHERE room_key=?',(room,)).fetchone()
    if not cand or not row or session['user_id'] not in (row['caller_id'],row['callee_id']): c.close(); return jsonify(error='Forbidden'),403
    field='caller_candidates' if session['user_id']==row['caller_id'] else 'callee_candidates'
    arr=json.loads(row[field] or '[]'); arr.append(cand)
    c.execute(f'UPDATE call_sessions SET {field}=? WHERE room_key=?',(json.dumps(arr),room)); c.commit(); c.close(); return jsonify(ok=True)

@app.route('/api/call/<room>/hangup',methods=['POST'])
@login_required
def call_hangup(room):
    c=db(); row=c.execute('SELECT * FROM call_sessions WHERE room_key=?',(room,)).fetchone()
    if not row or session['user_id'] not in (row['caller_id'],row['callee_id']): c.close(); return jsonify(error='Forbidden'),403
    c.execute("UPDATE call_sessions SET status='ENDED' WHERE room_key=?",(room,)); c.commit(); c.close(); return jsonify(ok=True)

@app.route('/admin/team/create',methods=['GET','POST'])
@role_required('admin')
def create_team_member():
    if request.method=='POST':
        name=request.form['name'].strip(); phone=request.form['phone'].strip(); password=request.form['password'].strip()
        if has_bad_words(name) or not name or not phone or len(password)<6:
            flash('Enter a valid name/phone and password of at least 6 characters.','error'); return redirect(url_for('create_team_member'))
        c=db()
        last=c.execute("SELECT member_id FROM users WHERE role='complaint_team' AND member_id IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        try: n=int(last['member_id'][2:])+1 if last and last['member_id'] and last['member_id'].startswith('CT') else 1
        except ValueError: n=1
        member_id=f'CT{n:03d}'; email=f'{member_id.lower()}@internal.loopify'
        c.execute("INSERT INTO users(name,email,phone,password_hash,role,member_id) VALUES(?,?,?,?,?,?)",(name,email,phone,generate_password_hash(password),'complaint_team',member_id))
        c.commit(); c.close(); flash(f'Complaint Team member {member_id} created. Save this ID for the member.','success'); return redirect(url_for('admin'))
    return render_template('team_create.html')

@app.route('/admin')
@role_required('admin')
def admin():
    c=db(); users=c.execute('SELECT id,name,email,phone,department,semester,role,member_id,created_at FROM users ORDER BY created_at DESC').fetchall(); products=c.execute('SELECT p.*,u.name owner_name FROM products p JOIN users u ON u.id=p.owner_id ORDER BY p.created_at DESC').fetchall(); stats={k:c.execute(q).fetchone()['c'] for k,q in {'users':'SELECT COUNT(*) c FROM users','products':'SELECT COUNT(*) c FROM products','out':'SELECT COUNT(*) c FROM products WHERE quantity=0','complaints':"SELECT COUNT(*) c FROM complaints WHERE status='OPEN'"}.items()}; team=c.execute("SELECT id,name,member_id,phone,created_at FROM users WHERE role='complaint_team' ORDER BY id").fetchall(); c.close(); return render_template('admin.html',users=users,products=products,stats=stats,team=team)


@app.route('/admin/delete/product/<int:pid>',methods=['POST'])
@role_required('admin')
def admin_delete_product(pid):
    c=db(); p=c.execute('SELECT photo FROM products WHERE id=?',(pid,)).fetchone(); c.execute('DELETE FROM products WHERE id=?',(pid,)); c.commit(); c.close();
    if p and p['photo']:(UPLOADS/p['photo']).unlink(missing_ok=True)
    flash('Product deleted.','success'); return redirect(url_for('admin'))


@app.route('/admin/delete/user/<int:uid>',methods=['POST'])
@role_required('admin')
def admin_delete_user(uid):
    if uid==session['user_id']: flash('You cannot delete your current admin account.','error'); return redirect(url_for('admin'))
    c=db(); c.execute('DELETE FROM users WHERE id=?',(uid,)); c.commit(); c.close(); flash('User deleted.','success'); return redirect(url_for('admin'))


@app.errorhandler(413)
def too_big(e): flash('Image is too large. Maximum is 5 MB.','error'); return redirect(url_for('sell'))

if __name__=='__main__':
    init_db(); app.run(debug=True)
