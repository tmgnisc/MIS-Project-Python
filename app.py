from flask import Flask, render_template, request, redirect, url_for, flash
import pandas as pd
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
# Replace with a secure secret key
app.config['SECRET_KEY'] = 'sheshraman'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Hardcoded username and password (replace with a more secure authentication method)
hardcoded_username = 'admin'
hardcoded_password = 'password'

# Change this to the path of your CSV file
CSV_FILE_PATH = 'C:/Users/sheshraman chaudhary/Desktop/dump.csv'


class User(UserMixin):
    pass


@login_manager.user_loader
def load_user(user_id):
    if user_id == hardcoded_username:
        user = User()
        user.id = user_id
        return user
    return None


def filter_data(domain):

    # Read CSV file and filter data based on the provided domain
    df = pd.read_csv(CSV_FILE_PATH)

    # Select only the desired columns
    selected_columns = ['Date', 'Name of the Employee', 'LOB', 'Supervisor', 'Part Full', 'Accepted', 'Avg Handle Time', 'Active Time', 'Ready Time', 'Not Ready Time', 'Busy Time', 'Occupancy', 'FCR Score (Sum)', 'NPS Score (Sum)', 'CSAT Score (Sum)', 'Quality Score']
    filtered_data = df[df['Domain Name'] == domain][selected_columns]

    #select the active column
    Accepted = pd.to_numeric(filtered_data['Accepted'], errors='coerce')
    Total_Accepted = Accepted.sum()


    avg_handle_time = filtered_data['Avg Handle Time'].replace('A', pd.NaT)
    #convert the avg handle time to time delta 
    avg_handle_time = pd.to_timedelta(avg_handle_time, errors='coerce')
    # drop rows with NaN values in the Avg Handle Time column
    avg_handle_time = avg_handle_time.mean()

    active_time = filtered_data['Active Time'].replace('A', pd.NaT)
    active_time = pd.to_timedelta(active_time, errors = 'coerce')
    total_active_time = active_time.sum()

    ready_time = filtered_data['Ready Time']
    ready_time = pd.to_timedelta(ready_time, errors = 'coerce')
    total_ready_time = ready_time.sum()


    not_ready_time = filtered_data['Not Ready Time']
    not_ready_time = pd.to_timedelta(not_ready_time, errors = 'coerce')
    total_not_ready_time = not_ready_time.sum()


    busy_time = filtered_data['Busy Time']
    busy_time = pd.to_timedelta(busy_time, errors = 'coerce')
    total_busy_time = busy_time.sum()

    occupancy = filtered_data['Occupancy']
    occupancy = pd.to_numeric(occupancy.str.rstrip('%'), errors='coerce')
    average_occupancy = occupancy.mean()

    fcr_score = filtered_data['FCR Score (Sum)']
    fcr_score = pd.to_numeric(fcr_score.str.rstrip('%'), errors='coerce')
    total_fcr_score = fcr_score.sum()
    total_fcr_count = df['FCR Count']
    total_fcr_count = total_fcr_count.sum()
    Fcr_Score = (total_fcr_score/total_fcr_count)*100



    nps_score = filtered_data['NPS Score (Sum)']
    nps_score = pd.to_numeric(nps_score.str.rstrip('%'), errors='coerce')
    total_nps_score = nps_score.sum()
    total_nps_count = df['NPS Count']
    total_nps_count = total_nps_count.sum()
    Nps_Score = (total_nps_score/total_nps_count)*100

    csat_score = filtered_data['CSAT Score (Sum)']
    csat_score = pd.to_numeric(csat_score.str.rstrip('%'), errors='coerce')
    total_csat_score = csat_score.sum()
    total_csat_count = df['CSAT Count']
    total_csat_count = total_csat_count.sum()
    Csat_Score = (total_csat_score/total_csat_count)*100

    quality_score = filtered_data['Quality Score']
    quality_score = pd.to_numeric(quality_score.str.rstrip('%'), errors='coerce')
    total_quality_score = quality_score.sum()
    total_quality_count = df['Quality Count']
    total_quality_count = total_quality_count.sum()
    Quality_Score = (total_quality_score/total_quality_count)*100

    # Create a dictionary to pass value to the HTML template

    result_dict = {
        'Accepted': Total_Accepted,
        'average_handle_time': avg_handle_time,
        'total_active_time': total_active_time,
        'total_ready_time': total_ready_time,
        'total_not_ready_time': total_not_ready_time,
        'total_busy_time': total_busy_time,
        'occupancy': average_occupancy,
        'total_fcr_score': Fcr_Score,
        'total_nps_score': Nps_Score,
        'total_csat_score': Csat_Score,
        'total_quality_score': Quality_Score
    }

    return filtered_data, result_dict


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Check username and password
        if form.username.data == hardcoded_username and form.password.data == hardcoded_password:
            user = User()
            user.id = form.username.data
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('admin'))  # Redirect to admin after successful login
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful', 'success')
    return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        filtered_data, result_dict  = filter_data(domain)
        return render_template('result.html', data=filtered_data.to_html(index=False), result_dict=result_dict)
    return render_template('index.html')


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    return render_template('admin.html')


@app.route('/update-csv', methods=['POST'])
@login_required
def update_csv():
    if 'csv_file' in request.files:
        csv_file = request.files['csv_file']
        new_csv_path = 'C:/Users/sheshraman chaudhary/Desktop/dump.csv'
        csv_file.save(new_csv_path)
        global CSV_FILE_PATH
        CSV_FILE_PATH = new_csv_path
        return redirect(url_for('admin'))
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=True)
