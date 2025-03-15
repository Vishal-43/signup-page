@app.route("/signup/", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        logging.debug(f"Signup POST request received with email: {email}")

        if password != confirm_password:
            logging.debug("Passwords do not match")
            return render_template('signup.html', password_error=True)

        existing_user = db.reference('users').order_by_child('email').equal_to(email).get()
        if (existing_user):
            logging.debug("Email already exists")
            return render_template('signup.html', email_exists_error=True)

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user_ref = db.reference('users').push({
            "name": name,
            "email": email,
            "password": hashed_password
        })
        user_id = new_user_ref.key

        # Create Firebase Auth user
        try:
            user = auth.create_user(
                uid=user_id,
                email=email,
                password=password
            )
            logging.debug("User created successfully. Redirecting to login page.")
            send_authentication_email(user)
            logging.debug("Email sent successfully.")
            return redirect(url_for('login', signup_success=True))
            
        except firebase_admin._auth_utils.EmailAlreadyExistsError:
            return render_template('signup.html', firebase_email_exists_error=True)
        except Exception as e:
            logging.error(f"Error creating user: {e}")
            return render_template('signup.html', general_error=str(e))
    signup_success = request.args.get('signup_success', False)

    return render_template('signup.html')
