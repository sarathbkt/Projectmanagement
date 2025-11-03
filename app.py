from flask import Flask, request, jsonify, session
from flask_cors import CORS
import pyodbc
import hashlib
import secrets
import datetime
from datetime import datetime, timedelta
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
CORS(app, supports_credentials=True)

# Database configuration
DB_CONFIG = {
    'server': 'your_server_name',
    'database': 'your_database_name',
    'username': 'your_username',
    'password': 'your_password',
    'driver': '{ODBC Driver 17 for SQL Server}'
}

def get_db_connection():
    """Create and return database connection"""
    conn_str = f"""
        DRIVER={DB_CONFIG['driver']};
        SERVER={DB_CONFIG['server']};
        DATABASE={DB_CONFIG['database']};
        UID={DB_CONFIG['username']};
        PWD={DB_CONFIG['password']}
    """
    return pyodbc.connect(conn_str)

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.headers.get('Authorization')
        if not session_token:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        user_data = validate_session_token(session_token)
        if not user_data:
            return jsonify({'success': False, 'message': 'Invalid or expired session'}), 401
        
        request.user_data = user_data
        return f(*args, **kwargs)
    return decorated_function

def validate_session_token(token):
    """Validate session token and return user data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT u.user_id, u.username, u.email, u.role, u.profile_name 
            FROM user_sessions us
            JOIN users u ON us.user_id = u.user_id
            WHERE us.session_token = ? AND us.expires_at > GETDATE()
        """, token)
        
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            return {
                'user_id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3],
                'profile_name': result[4]
            }
        return None
    except Exception as e:
        print(f"Session validation error: {e}")
        return None

# Authentication Routes
@app.route('/api/login', methods=['POST'])
def login():
    """Handle user login"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check user credentials
        cursor.execute("""
            SELECT user_id, username, email, role, profile_name, password_hash 
            FROM users 
            WHERE username = ? AND active = 1
        """, username)
        
        user = cursor.fetchone()
        
        if user and user[5] == hash_password(password):
            # Generate session token
            session_token = secrets.token_hex(32)
            expires_at = datetime.now() + timedelta(hours=24)
            
            # Store session
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            """, user[0], session_token, expires_at)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'sessionToken': session_token,
                'profileName': user[4],
                'email': user[2],
                'role': user[3]
            })
        else:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid credentials'})
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/validate-session', methods=['POST'])
def validate_session():
    """Validate existing session"""
    data = request.get_json()
    token = data.get('token')
    
    user_data = validate_session_token(token)
    if user_data:
        return jsonify({
            'valid': True,
            'userData': user_data
        })
    else:
        return jsonify({'valid': False})

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Handle user logout"""
    session_token = request.headers.get('Authorization')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM user_sessions WHERE session_token = ?", session_token)
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({'success': False}), 500

# Project Management Routes
@app.route('/api/projects', methods=['GET'])
@login_required
def get_projects():
    """Get projects based on status filter"""
    status_filter = request.args.get('status', 'planning')
    search_query = request.args.get('search', '')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Base query
        query = """
            SELECT 
                p.project_id,
                p.job_number,
                p.party_name,
                p.sales_order,
                p.status,
                p.salesman,
                p.order_type,
                p.assigned_to,
                p.start_date,
                p.end_date,
                p.kml_file,
                p.created_date
            FROM projects p
            WHERE 1=1
        """
        
        params = []
        
        # Add status filter
        if status_filter == 'planning':
            query += " AND p.status IN ('Planning', 'Draft', 'Scheduled')"
        elif status_filter == 'work':
            query += " AND p.status IN ('In Progress', 'Active')"
        elif status_filter == 'completed':
            query += " AND p.status IN ('Completed', 'Finished')"
        
        # Add search filter
        if search_query:
            query += " AND (p.job_number LIKE ? OR p.party_name LIKE ? OR p.sales_order LIKE ?)"
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param, search_param])
        
        query += " ORDER BY p.created_date DESC"
        
        cursor.execute(query, params)
        projects = cursor.fetchall()
        
        result = []
        for project in projects:
            result.append({
                'project_id': project[0],
                'job_number': project[1],
                'party_name': project[2],
                'sales_order': project[3],
                'status': project[4],
                'salesman': project[5],
                'order_type': project[6],
                'assigned_to': project[7],
                'start_date': project[8].strftime('%Y-%m-%d') if project[8] else None,
                'end_date': project[9].strftime('%Y-%m-%d') if project[9] else None,
                'kml_file': project[10],
                'created_date': project[11].strftime('%Y-%m-%d %H:%M:%S')
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'data': result})
        
    except Exception as e:
        print(f"Get projects error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch projects'}), 500

@app.route('/api/project/<int:project_id>', methods=['GET'])
@login_required
def get_project_details(project_id):
    """Get detailed project information"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get project basic info
        cursor.execute("""
            SELECT 
                project_id, job_number, party_name, sales_order, status,
                salesman, order_type, assigned_to, start_date, end_date, kml_file
            FROM projects 
            WHERE project_id = ?
        """, project_id)
        
        project = cursor.fetchone()
        
        if not project:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
        
        # Get sales order line items
        cursor.execute("""
            SELECT 
                stock_code, description, unit, quantity, 
                installed_quantity, balance_quantity
            FROM sales_order_items 
            WHERE project_id = ?
        """, project_id)
        
        so_items = []
        for item in cursor.fetchall():
            so_items.append({
                'stock_code': item[0],
                'description': item[1],
                'unit': item[2],
                'quantity': float(item[3]),
                'installed_quantity': float(item[4]),
                'balance_quantity': float(item[5])
            })
        
        # Get delivery note line items
        cursor.execute("""
            SELECT 
                stock_code, description, unit, quantity,
                installed_quantity, balance_quantity
            FROM delivery_note_items 
            WHERE project_id = ?
        """, project_id)
        
        dn_items = []
        for item in cursor.fetchall():
            dn_items.append({
                'stock_code': item[0],
                'description': item[1],
                'unit': item[2],
                'quantity': float(item[3]),
                'installed_quantity': float(item[4]),
                'balance_quantity': float(item[5])
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'project': {
                'project_id': project[0],
                'job_number': project[1],
                'party_name': project[2],
                'sales_order': project[3],
                'status': project[4],
                'salesman': project[5],
                'order_type': project[6],
                'assigned_to': project[7],
                'start_date': project[8].strftime('%Y-%m-%d') if project[8] else None,
                'end_date': project[9].strftime('%Y-%m-%d') if project[9] else None,
                'kml_file': project[10]
            },
            'so_line_items': so_items,
            'dn_line_items': dn_items
        })
        
    except Exception as e:
        print(f"Get project details error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch project details'}), 500

# Planning Routes
@app.route('/api/planning', methods=['POST'])
@login_required
def submit_planning():
    """Submit project planning data"""
    data = request.get_json()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update project with planning data
        cursor.execute("""
            UPDATE projects 
            SET start_date = ?, end_date = ?, site_engineer = ?, 
                project_incharge = ?, kml_file = ?, status = 'Scheduled'
            WHERE project_id = ?
        """, 
        data['start_date'], data['end_date'], data['site_engineer'],
        data['project_incharge'], data['kml_file'], data['project_id'])
        
        # Log planning activity
        cursor.execute("""
            INSERT INTO project_activities 
            (project_id, activity_type, description, created_by, created_date)
            VALUES (?, 'Planning', 'Project planning submitted', ?, GETDATE())
        """, data['project_id'], request.user_data['user_id'])
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Planning submitted successfully'})
        
    except Exception as e:
        print(f"Planning submission error: {e}")
        return jsonify({'success': False, 'message': 'Failed to submit planning'}), 500

# Work Progress Routes
@app.route('/api/work-progress', methods=['POST'])
@login_required
def submit_work_progress():
    """Submit work progress update"""
    data = request.get_json()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update installed quantities
        for item in data.get('so_line_items', []):
            cursor.execute("""
                UPDATE sales_order_items 
                SET installed_quantity = installed_quantity + ?,
                    balance_quantity = quantity - (installed_quantity + ?),
                    last_updated = GETDATE()
                WHERE project_id = ? AND stock_code = ?
            """, item['today_installed'], item['today_installed'], 
            data['project_id'], item['stock_code'])
        
        for item in data.get('dn_line_items', []):
            cursor.execute("""
                UPDATE delivery_note_items 
                SET installed_quantity = installed_quantity + ?,
                    balance_quantity = quantity - (installed_quantity + ?),
                    last_updated = GETDATE()
                WHERE project_id = ? AND stock_code = ?
            """, item['today_installed'], item['today_installed'], 
            data['project_id'], item['stock_code'])
        
        # Save manpower entries
        for manpower in data.get('manpower', []):
            cursor.execute("""
                INSERT INTO manpower_entries 
                (project_id, source, quantity, entry_date, created_by)
                VALUES (?, ?, ?, GETDATE(), ?)
            """, data['project_id'], manpower['source'], 
            manpower['quantity'], request.user_data['user_id'])
        
        # Save equipment entries
        for equipment in data.get('equipment', []):
            cursor.execute("""
                INSERT INTO equipment_entries 
                (project_id, equipment_name, source, quantity, cost, entry_date, created_by)
                VALUES (?, ?, ?, ?, ?, GETDATE(), ?)
            """, data['project_id'], equipment['name'], 
            equipment['source'], equipment['quantity'], 
            equipment['cost'], request.user_data['user_id'])
        
        # Log progress activity
        cursor.execute("""
            INSERT INTO project_activities 
            (project_id, activity_type, description, created_by, created_date)
            VALUES (?, 'Progress', 'Work progress updated', ?, GETDATE())
        """, data['project_id'], request.user_data['user_id'])
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Work progress updated successfully'})
        
    except Exception as e:
        print(f"Work progress submission error: {e}")
        return jsonify({'success': False, 'message': 'Failed to update work progress'}), 500

# Utility Routes
@app.route('/api/dropdown-options', methods=['GET'])
@login_required
def get_dropdown_options():
    """Get dropdown options for forms"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get site engineers
        cursor.execute("SELECT DISTINCT engineer_name FROM site_engineers WHERE active = 1")
        site_engineers = [row[0] for row in cursor.fetchall()]
        
        # Get project incharges
        cursor.execute("SELECT DISTINCT incharge_name FROM project_incharges WHERE active = 1")
        project_incharges = [row[0] for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'siteEngineers': site_engineers,
            'projectIncharges': project_incharges
        })
        
    except Exception as e:
        print(f"Dropdown options error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch dropdown options'}), 500

@app.route('/api/equipment-list', methods=['GET'])
@login_required
def get_equipment_list():
    """Get equipment list for dropdown"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT equipment_name FROM equipment_master WHERE active = 1")
        equipment_list = [row[0] for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return jsonify(equipment_list)
        
    except Exception as e:
        print(f"Equipment list error: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch equipment list'}), 500

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    data = request.get_json()
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify current password
        cursor.execute("""
            SELECT password_hash FROM users 
            WHERE user_id = ?
        """, request.user_data['user_id'])
        
        result = cursor.fetchone()
        
        if not result or result[0] != hash_password(current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        # Update password
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?, last_password_change = GETDATE()
            WHERE user_id = ?
        """, hash_password(new_password), request.user_data['user_id'])
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
        
    except Exception as e:
        print(f"Password change error: {e}")
        return jsonify({'success': False, 'message': 'Failed to change password'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)