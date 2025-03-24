## Prerequisites

* A Windows 10 or 11 computer with internet connection
* At least 4GB of RAM and 10GB of free disk space

## Installation Steps

**Step 1: Install Docker Desktop**

1.  Download Docker Desktop for Windows from the official website:
    * Go to [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)
    * Click on the "Download for Windows" button
2.  Run the installer:
    * Double-click the downloaded file (typically named "Docker Desktop Installer.exe")
    * Follow the on-screen instructions
    * When prompted, ensure the "Use WSL 2 instead of Hyper-V" option is selected (if available)
    * Allow the installer to make changes to your device when prompted
    * Click "Ok" to begin installation
    
3.  Restart your computer when the installation is complete
4.  After restarting, Docker Desktop will start automatically. You'll see the Docker icon in your system tray (near the clock in the taskbar).
5. You might see a popup asking to install additional components - click "Install" if prompted
6. Wait for Docker Desktop to complete its startup (you'll see a green "Docker Desktop is running" message)


**Step 2: Download the School Fee Management System**

1.  Download the application from GitHub:
    * Go to the GitHub repository 
    * Look for a green "Code" button and click it
    * Select "Download ZIP"
    * Save the ZIP file to your computer
2.  Extract the ZIP file:
    * Right-click on the ZIP file
    * Select "Extract All..."
    * Choose a destination folder (or use the default)
    * Click "Extract"

**Step 3: Run the Application**

1.  Open Command Prompt:
    * Press the Windows key
    * Type "cmd"
    * Click on "Command Prompt" in the search results
2.  Navigate to the application folder:
    * Type `cd` followed by the path to where you extracted the files
    * For example: `cd C:\Users\YourName\Desktop\school_fee_management`
    * Press Enter
3.  Start the application:
    * Type: `docker-compose up -d`
    * Press Enter
    * Wait for the process to complete (this may take a few minutes the first time)
    * You'll see Docker downloading and setting up the application
4.  The application is now running!

**Step 4: Access the Application**

1.  Open your web browser (like Chrome, Edge, or Firefox)
2.  In the address bar, type: `http://localhost:5000`
3.  The School Fee Management System login page should appear

## Using the Application

* If it's your first time, create an account with Admin role. You will be authenticated automatically.

## Stopping the Application

* When you're done using the application:
    1.  Open Command Prompt again (if it's closed)
    2.  Navigate to the application folder as you did in Step 3
    3.  Type: `docker-compose down`
    4.  Press Enter

## Restarting the Application Later

* To start the application again later:
    1.  Make sure Docker Desktop is running (check for the icon in your system tray)
    2.  Open Command Prompt
    3.  Navigate to the application folder
    4.  Type: `docker-compose up -d`
    5.  Press Enter

## Troubleshooting

* **If the application doesn't start:**
    * Make sure Docker Desktop is running:
        * Look for the Docker icon in the system tray
        * If it's not there, search for "Docker Desktop" in the Start menu and open it
    * Check for error messages:
        * In Command Prompt, type: `docker-compose logs`
        * Press Enter to see if there are any error messages
* **If you can't access the website:**
    * Verify the application is running:
        * In Command Prompt, type: `docker ps`
        * Press Enter
        * You should see at least two containers running (web and db)
    * Try accessing with a different browser
    * Restart the application:
        * Type: `docker-compose down`
        * Press Enter
        * Then type: `docker-compose up -d`
        * Press Enter
* **If Docker Desktop won't install:**
    * Make sure your Windows version is up to date
    * Enable virtualization in BIOS (you might need technical assistance for this)

## Need Help?

If you encounter any issues not covered in the troubleshooting section, please contact technical support at [uthkarsh.31@gmail.com]