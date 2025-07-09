import streamlit as st
import json
import os
import re
import string
import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder,MinMaxScaler
from time import sleep
from datetime import datetime
from keras.models import load_model

import pickle
session_state = st.session_state
if "is_running" not in st.session_state:
        st.session_state.is_running = False
if "sample_data" not in st.session_state:
        st.session_state.sample_data = pd.read_csv('sample_data.csv')
if "user_index" not in st.session_state:
    st.session_state["user_index"] = 0


def signup(json_file_path="data.json"):
    st.title("Signup Page")
    with st.form("signup_form"):
        st.write("Fill in the details below to create an account:")
        name = st.text_input("Name:")
        email = st.text_input("Email:")
        age = st.number_input("Age:", min_value=0, max_value=120)
        sex = st.radio("Sex:", ("Male", "Female", "Other"))
        password = st.text_input("Password:", type="password")
        confirm_password = st.text_input("Confirm Password:", type="password")

        if st.form_submit_button("Signup"):
            if password == confirm_password:
                user = create_account(
                    name,
                    email,
                    age,
                    sex,
                    password,
                    json_file_path,
                )
                session_state["logged_in"] = True
                session_state["user_info"] = user
            else:
                st.error("Passwords do not match. Please try again.")


def check_login(username, password, json_file_path="data.json"):
    try:
        with open(json_file_path, "r") as json_file:
            data = json.load(json_file)

        for user in data["users"]:
            if user["email"] == username and user["password"] == password:
                session_state["logged_in"] = True
                session_state["user_info"] = user
                st.success("Login successful!")
                return user
        return None
    except Exception as e:
        st.error(f"Error checking login: {e}")
        return None


def initialize_database(json_file_path="data.json"):
    try:
        if not os.path.exists(json_file_path):
            data = {"users": []}
            with open(json_file_path, "w") as json_file:
                json.dump(data, json_file)
    except Exception as e:
        print(f"Error initializing database: {e}")


def create_account(
    name,
    email,
    age,
    sex,
    password,
    json_file_path="data.json",
):
    try:
        # Check if the JSON file exists or is empty
        if not os.path.exists(json_file_path) or os.stat(json_file_path).st_size == 0:
            data = {"users": []}
        else:
            with open(json_file_path, "r") as json_file:
                data = json.load(json_file)

        # Append new user data to the JSON structure
        user_info = {
            "name": name,
            "email": email,
            "age": age,
            "sex": sex,
            "password": password,
            "report": None,
            "questions": None,
        }
        data["users"].append(user_info)

        # Save the updated data to JSON
        with open(json_file_path, "w") as json_file:
            json.dump(data, json_file, indent=4)

        st.success("Account created successfully! You can now login.")
        return user_info
    except json.JSONDecodeError as e:
        st.error(f"Error decoding JSON: {e}")
        return None
    except Exception as e:
        st.error(f"Error creating account: {e}")
        return None


def login(json_file_path="data.json"):
    st.title("Login Page")
    username = st.text_input("Email:")
    password = st.text_input("Password:", type="password")

    login_button = st.button("Login")

    if login_button:
        user = check_login(username, password, json_file_path)
        if user is not None:
            session_state["logged_in"] = True
            session_state["user_info"] = user
        else:
            st.error("Invalid credentials. Please try again.")


def get_user_info(email, json_file_path="data.json"):
    try:
        with open(json_file_path, "r") as json_file:
            data = json.load(json_file)
            for user in data["users"]:
                if user["email"] == email:
                    return user
        return None
    except Exception as e:
        st.error(f"Error getting user information: {e}")
        return None

def render_dashboard(user_info, json_file_path="data.json"):
    try:
        st.title(f"Welcome to the Dashboard, {user_info['name']}!")
        st.subheader("User Information:")
        st.write(f"Name: {user_info['name']}")
        st.write(f"Sex: {user_info['sex']}")
        st.write(f"Age: {user_info['age']}")

    except Exception as e:
        st.error(f"Error rendering dashboard: {e}")
    
def main(json_file_path="data.json"):
    
    st.sidebar.title("Network Intrusion Detection App")
    page = st.sidebar.radio(
        "Go to",
        ("Signup/Login", "Dashboard", "Network Intrusion Detection App"),
        key="Intrusion Detection App",
    )

    if page == "Signup/Login":
        st.title("Signup/Login Page")
        login_or_signup = st.radio(
            "Select an option", ("Login", "Signup"), key="login_signup"
        )
        if login_or_signup == "Login":
            login(json_file_path)
        else:
            signup(json_file_path)

    elif page == "Dashboard":
        if session_state.get("logged_in"):
            render_dashboard(session_state["user_info"])
        else:
            st.warning("Please login/signup to view the dashboard.")

    elif page == "Network Intrusion Detection App":
        if session_state.get("logged_in"):
            st.markdown("<h1 style='color:blue;'>Network Intrusion Detection App</h1>", unsafe_allow_html=True)
            st.write("Click below to start predicting if their is an Intrusion or not:")
            
            # Display the saved image
            # st.image('img1.png', use_column_width=True)
            label_mappings_dict={0: 'BENIGN', 1: 'Bot', 2: 'DDoS', 3: 'DoS GoldenEye', 4: 'DoS Hulk', 5: 'DoS Slowhttptest', 6: 'DoS slowloris', 7: 'FTP-Patator', 8: 'Heartbleed', 9: 'Infiltration', 10: 'PortScan', 11: 'SSH-Patator', 12: 'Web Attack � Brute Force', 13: 'Web Attack � Sql Injection', 14: 'Web Attack � XSS'}
            X_1 = pd.read_csv('sample_data.csv')
            # with open('scaler.pkl', 'rb') as f:
            #     scaler = pickle.load(f)

            model_filename = 'model.keras'
            model = load_model(model_filename)

            

            start_button_clicked = st.button("Start", key="start_button", help="Click to start predicting")
            stop_button_clicked = st.button("Stop", key="stop_button", help="Click to stop predicting")
            
            data_placeholder = st.empty()
            prediction_placeholder = st.empty()
            def process_csv_with_delay(sampled_data, model, st):
                while st.session_state.is_running:
                    if len(sampled_data) == 0:
                        sampled_data = pd.read_csv('sample_data.csv')
                        continue
                    
                    row = sampled_data.iloc[0]
                    
                    sample = row.values.reshape(1, -1)
    
                    # Use the model for prediction
                    prediction = model.predict(sample)
                    predicted_class = prediction.argmax()
    
                    # Map the predicted class index to the actual label
                    actual_label = label_mappings_dict[predicted_class]
                    # Print the result with timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    data_placeholder.write(f'Network Data : {row}')
                    if actual_label != 'BENIGN':
                        prediction_placeholder.markdown(f"<p style='color:red; font-size:20px;'>Time : {timestamp} - Danger !!! You are Under Attack ----> Attack Type: {actual_label}  </p>", unsafe_allow_html=True)
                    else:
                        prediction_placeholder.markdown(f"<p style='color:green; font-size:20px;'>Time: {timestamp} - No attack detected</p>", unsafe_allow_html=True)
                    
                    sampled_data = sampled_data.iloc[1:]
                    st.session_state.sampled_data = sampled_data.to_json()  # Store the updated sampled_data in session state
                    sleep(5)
                    
                    if not st.session_state.is_running:
                        break
            if start_button_clicked:
                st.session_state.is_running = True
                process_csv_with_delay(X_1, model, st)

            if stop_button_clicked:
                st.session_state.is_running = False
        else:
            st.warning("Please login/signup to use the app!!")
    else:
        st.warning("Please login/signup to use the app!!")


if __name__ == "__main__":
    initialize_database()
    main()
