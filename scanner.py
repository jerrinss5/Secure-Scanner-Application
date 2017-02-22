# to get flask and ites related functions
from flask import Flask, request, render_template, session, redirect, flash, url_for
# to calculate session time out
from datetime import timedelta
# to hash, generate salt, use os function, use regular expression and file header check
import hashlib, uuid, os, sys, re, magic
# to connect to mongo client
from pymongo import MongoClient
# to read config files
import configparser
# to execute system commands
import subprocess


def load_config_file():
    # the path where config file exists
    config_file_path = r'config.txt'
    # load config parser
    config_parser = configparser.RawConfigParser()
    # load the config file using the parser
    config_parser.read(config_file_path)
    # returning the config parser object
    return config_parser


def assign_session_key():
    # calling the config parser function
    config_parser = load_config_file()
    # get the session key from configuration
    app.secret_key = config_parser.get('session-config', 'session_key')


app = Flask(__name__)
assign_session_key()


@app.before_request
def make_session_permanent():
    # session will remain valid even if the browser is closed
    session.permanent = True
    # session will remain valid till 5 minutes
    app.permanent_session_lifetime = timedelta(minutes=5)
    # app.permanent_session_lifetime = timedelta(seconds=10)


@app.route('/', methods=['GET'])
def index():
    # by default open the index page
    return render_template('index.html')


@app.route('/home', methods=['GET'])
def home():
    try:
        # check if the user is allowed to access this page
        valid = user_check()
        if valid:
            # get the user name from session
            username = session['username']
            file_name, file_type, flawfinder_output, rats_output = get_user_details(session['user_id'])
            return render_template('home.html', username=username, file_name=file_name,
                                   file_type=file_type, flawfinder_output=flawfinder_output,
                                   rats_output=rats_output)
        else:
            flash("please log in!")
            return redirect(url_for("index"), code=302)
    except:
        flash("please log in!")
        return redirect(url_for("index"), code=302)


def open_mongo_connection():
    try:
        # get the config parser object reading the config file
        config_parser = load_config_file()
        # get db user name from config file
        db_username = config_parser.get('DB-config', 'username')
        # get db password from config file
        db_password = config_parser.get('DB-config', 'password')
		# get db url from config file
		db_url = config_parser.get('DB-config', 'connect_url')
        # generate the mongo url from the username and password from the file
        mongo_url = "mongodb://" + str(db_username) + ":" + str(db_password) + str(db_url)
        mongo_url = mongo_url.replace("\"", "")
        # connect to the url and get the client object
        client = MongoClient(mongo_url)
        # client = MongoClient("mongodb://localhost:27017")
        # connect to securedb database in mongodb
        db = client.securedb
        return db, client
    except:
        flash("Unable to connect to MongoDB! Try Again")
        return redirect(url_for("index"), code=302)


def close_mongo_db_connection(client):
    try:
        # close the mongo db connection
        client.close()
    except:
        flash("Some error occurred")
        return redirect(url_for("index"), code=302)


@app.route('/login', methods=['POST'])
def login():
    try:
        client = None
        # getting user name from user
        username = request.form['username']
        # check if username is not blank
        if username == "":
            flash("Username cannot be blank")
            return redirect(url_for('index'), code=302)
        # white list check for username
        match = username_validation(username)
        if not match:
            flash("Username can contain only alphabets, numbers and underscore 1 to 15 chars long")
            return redirect(url_for('index'), code=302)
        # getting password from the user
        password = request.form['password']
        # check if the password is not blank
        if password == "":
            flash("password cannot be blank")
            return redirect(url_for('index'), code=302)
        # white list check for password
        match = password_validation(password)
        if not match:
            flash("Password can only be 4 to 15 chars long and can contain ! @ # $ % ^ & * ( )")
            return redirect(url_for('index'), code=302)
        # opening the database connection
        db, client = open_mongo_connection()
        # query to check if the user name inputted is valid
        user_query = {
            'username': username
        }
        # connecting to the user collection
        user_collection = db.user
        # firing the find query against the user collection
        user_dict = user_collection.find_one(user_query)
        # closing the database connection
        close_mongo_db_connection(client)

        # checking if the query returned any output
        if user_dict:
            # storing the username and user id in session variable
            session['user_id'] = str(user_dict['_id'])
            session['username'] = str(user_dict['username'])
            # get salt from database
            salt = user_dict['salt']
            # get hashed password from database
            hashed_password_db = user_dict['password']
            # generate hash for the combination of password and salt
            hash_password = hex_generator(password + salt)
            # match password from db and user given
            if hashed_password_db == hash_password:
                # get user related details as it is a valid user
                return redirect(url_for('home'), code=302)
            else:
                # invalid password
                flash("Invalid username or password")
                return redirect(url_for('index'), code=302)
        else:
            # user not available
            flash("Invalid username or password")
            return redirect(url_for('index'), code=302)

    except:  # get failure message
        e = sys.exc_info()[0]
        print e
        flash("Some error occurred")
        return redirect(url_for('index'), code=302)
    finally:
        # to erase data stored in password
        password = ""
        password += ""
        if client:
            close_mongo_db_connection(client)


@app.route('/register_redirect', methods=['get'])
def register_redirect():
    return render_template('register.html')


@app.route("/register", methods=['POST'])
def register():
    try:
        client = None
        # get username from user
        username = request.form['username']
        if username == "":
            flash("Username cannot be blank")
            return redirect(url_for('register_redirect'), code=302)
        # white list check for username
        match = username_validation(username)
        if not match:
            flash("Invalid username. Username can contain only alphabets, numbers and underscore 1 to 15 chars long")
            return redirect(url_for('register_redirect'), code=302)
        # get password from user
        password = request.form['password']
        if password == "":
            flash("Password cannot be blank")
            return redirect(url_for('register_redirect'), code=302)
        # white list check for password
        match = password_validation(password)
        if not match:
            flash("Password can only be 4 to 15 chars long and can contain ! @ # $ % ^ & * ( )")
            return redirect(url_for('register_redirect'), code=302)
        # get random salt
        salt = uuid.uuid4().hex
        # generating hash password plus salt
        hash_password = hex_generator(password + salt)
        # generating the insertion query
        user_entry = {
            'username': username,
            'password': hash_password,
            'salt': salt
        }
        # query to check if the user name already exists
        user_query = {
            'username': username
        }
        # opening the mongo connection
        db, client = open_mongo_connection()

        # connecting to the user collection
        user_collection = db.user
        # firing the find query against the user collection
        user_dict = user_collection.find_one(user_query)
        if user_dict:
            flash("Username already exists!")
            return redirect('register_redirect', code=302)
        # creating a user table - collection
        user_collection = db.user

        # inserting user supplied data
        user = user_collection.insert(user_entry)

        # if user object is not None
        if user:
            flash("Registered successfully")
        else:
            flash("Registration failed")

        # closing mongo db connection
        close_mongo_db_connection(client)
        print 'test'
        return redirect(url_for('index'), code=302)

    except:
        flash("some error occurred")
        return redirect(url_for('index'), code=302)

    finally:
        # erasing password assigment operator
        password = ""

        # using the password so that the compiler assigns the value at the background
        password += ""
        if client:
            close_mongo_db_connection(client)


@app.route('/file_upload', methods=['POST'])
def file_upload():
    try:
        client = None
        # initializing the file type to none
        file_type = None
        # check if the user is a valid user
        valid = user_check()
        if not valid:
            flash("Please login to upload")
            return redirect(url_for('index'), code=302)
        # getting the username from session
        username = session['username']
        # getting the user id from session
        user_id = session['user_id']
        # initializing file variable to none
        file1 = None
        # file object reference
        file1 = request.files['datafile']
        # if no file is selected
        if not file1:
            flash("No file selected to be scanned")
            return redirect(url_for('home'), code=302)
        # name of the file uploaded
        file_name = file1.filename

        match = filename_validation(file_name)
        if not match:
            flash("Invalid file name it can contain only alphabets, numbers, underscore and period, 1 to 15 chars long")
            return redirect(url_for('home'), code=302)

        # contents of the file uploaded
        file_content = file1.read()

        # Size of the file uploaded
        file_size = len(file_content)

        if file_size > 3000000:
            flash("File size exceeded 3MB! Please upload a smaller file!")
            return redirect(url_for('home'), code=302)

        if file_size <= 0:
            flash("File size 0 bytes!")
            return redirect(url_for('home'), code=302)

        # check if the file type is valid
        file_ext_valid, file_type = file_extension_check(file_content)
        # if not valid inform the user
        if not file_ext_valid:
            flash("Invalid file type uploaded. Type: " + file_type + " Allowed: C/C++, python, perl and PHP")
            return redirect(url_for('home'), code=302)

        # unix style
        user_data_dir = "user_data/" + username
        # windows style
        # user_data_dir = "user_data\\" + username
        # making directory with username
        if not os.path.exists(user_data_dir):
            os.makedirs(user_data_dir)
        # opening the file with file name in write mode
        code_file = open(os.path.join("user_data", username, file_name), 'w')
        # writing the file content to the file opened
        code_file.write(file_content)
        # closing the file handler
        code_file.close()
        # calling the scanner
        # tools output folder name
        flawfinder_output_filename = ""
        rats_output_filename = ""
        flawfinder_output_content = "no"
        rats_output_content = "no"

        if file_type == 'C source':
            flawfinder_output_filename = os.path.join("user_data", username, file_name) + "_flawfinder.txt"
            rats_output_filename = os.path.join("user_data", username, file_name) + "_rats.txt"
            flawfinder_system_query = "flawfinder " + os.path.join("user_data", username,
                                                                   file_name) + " > " + flawfinder_output_filename

            rats_system_query = "rats -w 3 " + os.path.join("user_data", username,
                                                            file_name) + " > " + rats_output_filename
            flawfinder_output_content = ""
            rats_output_content = ""
            subprocess.Popen(flawfinder_system_query, shell=True)
            subprocess.Popen(rats_system_query, shell=True)
        else:
            rats_output_filename = os.path.join("user_data", username, file_name) + "_rats.txt"
            rats_system_query = "rats -w 3 " + os.path.join("user_data", username,
                                                            file_name) + " > " + rats_output_filename
            rats_output_content = ""
            subprocess.Popen(rats_system_query, shell=True)

        # making entry on to the database
        output_store = {
            'user_id': user_id,
            'file_type': file_type,
            'file_name': file_name,
            'flawfinder_output': flawfinder_output_content,
            'rats_output': rats_output_content
        }

        # opening mongo connection
        db, client = open_mongo_connection()

        # creating a user output table - collection
        user_collection = db.user_output

        # inserting user supplied data
        user_collection.insert(output_store)

        # closing the mongo connection
        close_mongo_db_connection(client)

        flash("uploaded successfully! Scanning started!!")

        return redirect('home', code=302)

    except:
        e = sys.exc_info()
        print e
        flash("some error occurred while uploading")
        return redirect(url_for("home"), code=302)

    finally:
        if client:
            close_mongo_db_connection(client)


@app.route('/logout', methods=['GET'])
def logout():
    try:
        valid = user_check()
        if valid:
            username = session['username']
            session.pop('username', None)
            # session.clear()
            flash("Logged out successfully")
        else:
            flash("please log in!")
    except:
        flash("Some exception occurred")
    return redirect(url_for("index"), code=302)


def hex_generator(password_salt):
    hash_password_obj = hashlib.sha256(password_salt)
    hash_password = hash_password_obj.hexdigest()
    return hash_password


def username_validation(str_match):
    pattern = '^[a-z0-9A-Z_]{1,15}$'
    match = matching(pattern, str_match)
    return match


def password_validation(str_match):
    pattern = '^[a-z0-9A-Z._!@#$%^&*]{4,15}$'
    match = matching(pattern, str_match)
    return match


def filename_validation(str_match):
    pattern = '^[a-z0-9A-Z._]{1,15}$'
    match = matching(pattern, str_match)
    return match


def matching(pattern, str_match):
    match = False
    matchObj = re.match(pattern, str_match, flags=0)
    if matchObj:
        match = True
    else:
        match = False
    return match


def user_check():
    try:
        if 'username' in session:
            valid = True
        else:
            valid = False
    except:
        valid = False
    return valid


def file_extension_check(file_content):
    valid = False
    # check from buffer what is the extension
    ext_type = str(magic.from_buffer(file_content))
    file_type = ext_type.split(",")[0]
    if file_type == "C source" or file_type == "Python script" or file_type == "a /usr/bin/perl script" or \
                    file_type == "PHP script" or file_type == "HTML document":
        valid = True
    return valid, file_type


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            print 'csrf invalid'
            return render_template('index.html')


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = uuid.uuid4().hex
    return session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def get_user_details(user_id):
    user_search = {
        'user_id': user_id
    }
    # opening mongo connection
    db, client = open_mongo_connection()

    # creating a user output table - collection
    user_collection = db.user_output

    # inserting user supplied data
    user_details = user_collection.find(user_search)

    # closing the database connection
    close_mongo_db_connection(client)

    # getting the username
    username = session['username']

    # initializing
    file_type = list()
    file_name = list()
    rats_output = list()
    flawfinder_output = list()
    flawfinder_output_content = ""
    rats_output_content = ""

    if user_details:
        for user_detail in user_details:
            flawfinder_done = False
            rats_done = False
            flawfinder_output_content = ""
            rats_output_content = ""
            # get the file type from database
            file_type.append(user_detail['file_type'])
            # get the file name from database
            file_name.append(user_detail['file_name'])
            # get the source file name with relative position
            source_file_name = os.path.join("user_data", username, user_detail['file_name'])
            # get the flawfinder output name with relative position
            flawfinder_output_filename = os.path.join("user_data", username,
                                                      user_detail['file_name']) + "_flawfinder.txt"
            # get the rats output name with relative position
            rats_output_filename = os.path.join("user_data", username, user_detail['file_name']) + "_rats.txt"
            # checking if the flawfinder output has already been found
            if user_detail['flawfinder_output'] == "":
                # if not found open the output file in read mode
                flawfinder_output_file = open(flawfinder_output_filename, 'r')
                # read the contents of the file
                flawfinder_output_content = flawfinder_output_file.read()
                # close the file handler
                flawfinder_output_file.close()
                # remove the file as data stored to the database
                os.remove(flawfinder_output_filename)
                # set the operation as done
                flawfinder_done = True
            else:
                # if data is in database fetch it from there
                data = str(user_detail['flawfinder_output'])
                # side condition to handle
                flawfinder_output_content = data.replace("no", "")
            # append the result to the list
            flawfinder_output.append(flawfinder_output_content)

            if user_detail['rats_output'] == "":
                rats_output_file = open(rats_output_filename, 'r')
                rats_output_content = rats_output_file.read()
                rats_output_file.close()
                os.remove(rats_output_filename)
                rats_done = True
            else:
                rats_output_content = user_detail['rats_output']
            rats_output.append(rats_output_content)

            # updating the data to the mongo database
            user_detail_id = {
                "_id": user_detail['_id']
            }

            # opening mongo connection
            db, client = open_mongo_connection()

            # creating a user output table - collection
            user_collection = db.user_output

            if flawfinder_done:
                flawfinder_update = {
                    'flawfinder_output': flawfinder_output_content
                }
                set_update = {
                    '$set': flawfinder_update
                }
                # updating the flawfinder output to mongo db
                user_collection.update(user_detail_id, set_update)

            if rats_done:
                rats_update = {
                    'rats_output': rats_output_content
                }
                set_update = {
                    '$set': rats_update
                }
                # updating the rats output to mongo db
                user_collection.update(user_detail_id, set_update)

            # closing the mongodb connection
            close_mongo_db_connection(client)

            if os.path.exists(source_file_name) and (flawfinder_done or rats_done):
                # removing the user uploaded file
                os.remove(source_file_name)
                # removing the directory created for the users
                os.rmdir('user_data/' + username)

    return file_name, file_type, flawfinder_output, rats_output


if __name__ == "__main__":
    app.run()
