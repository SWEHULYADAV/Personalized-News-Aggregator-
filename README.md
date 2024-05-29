# Personalized-News-Aggregator-
Personalized News Aggregator: A Flask-based web application that aggregates top news headlines and provides a personalized news feed based on user preferences. Users can sign up, log in, and customize their news feed by selecting preferred categories. Built with Python, Flask, SQLite, bcrypt, and News API.
=====================================================
Execution Of Project Via GitHub
=====================================================
1. Git Clone:
   - Open a command prompt.
Here In My Case I'm Using Anaconda Prompt For Executing ....
   - Navigate to the directory where you want to clone the repository. For example, if you want to clone it on the desktop:

     ```
     cd Desktop
     ```

   - Clone the repository:

     ```
     git clone https://github.com/SWEHULYADAV/Personalized-News-Aggregator-.git
     ```
And Install Packages By Command

     pip install Flask Flask-WTF bcrypt requests Werkzeug
     ```
2. Navigate to Project Directory:
   - Change your directory to the cloned project folder:

     ```
     cd Personalized-News-Aggregator-
     ```

3. Create and Activate Virtual Environment (venv):
   - Run the following command to create a virtual environment:

     ```
     python -m venv venv
     ```

   - Activate the virtual environment:

     ```
     venv\Scripts\activate
     ```

4. Install Dependencies:
   - Ensure you are in the virtual environment (your command prompt should start with `(venv)`).
   - Install the dependencies:

     ```
     pip install -r requirements.txt
     ```

5. Run the Application:
   - Once all the dependencies are installed, you can run your Flask application:

     ```
     python app.py
     ```

6. Access Your Application:
    - Open your web browser and enter the following URL in the address bar:

      ```
      http://127.0.0.1:5000/
      ```

    - This link connects to your local server, and you should see your personalized news aggregator application in action.
-----------------------------------------------------
=====================================================

EXECUTING THE PROJECT OFFLINE - STEP-BY-STEP GUIDE:

=====================================================

-----------------------------------------------------

1. Open Anaconda Navigator:
   - Launch the Anaconda Navigator application.

2. Navigate to the Environments Tab:
   - On the home page of Navigator, go to the "Environments" tab.

3. Create a New Environment:
   - Click "Create" to make a new environment.
   - Give it a name, like "PersonalizedNewsAggregator".

4. Install Required Packages:
   - After creating, select the "Not Installed" filter.
   - Install packages: `flask`, `click`, `itsdangerous`, `Jinja2`, `MarkupSafe`, `Werkzeug`.

5. Open the Terminal:
   - Go back to the home page, click "Home," and then click "Open Terminal."

6. Navigate to Project Folder:
   - In the terminal, go to the folder where your project is located. For example:

     ```
     cd C:\Users\12\Desktop\12  (here your file location will be there)
     ```

7. Activate the Virtual Environment (Optional):
   - If you want to create and activate a virtual environment, follow these steps:
     - Create a new virtual environment:

       ```
       conda create --name PersonalizedNewsAggregator python=3.8
       ```

     - Activate the virtual environment:

       ```
       conda activate PersonalizedNewsAggregator
       ```

   - If you prefer not to create a virtual environment and use your base Anaconda environment, you can skip this step.

8. Install Dependencies:
   - In the same terminal, within your project folder, where `requirements.txt` is located, run:

     ```
     pip install -r requirements.txt
     ```

   - This will install all necessary dependencies for your project.

9. Run the Application:
   - Still in the terminal, in your project folder, where `app.py` is located, run:

     ```
     python app.py
     ```

   - This command will start your Flask application. You will see a URL in the terminal; copy and paste it into your browser to view the application.
  
10. Access Your Application:
    - Open your web browser and enter the following URL in the address bar:

      ```
      http://127.0.0.1:5000/
      ```

    - This link connects to your local server, and you should see your personalized news aggregator application in action.
