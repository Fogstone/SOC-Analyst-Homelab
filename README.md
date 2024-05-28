This is a report based on a homelab created using LimaCharlie EDR with Sysmon and VMWare for lab containers.

**<h2>Initial Setup:</h2>**

This lab involves the use of two virtual machines: one serving as an attack machine while the other is used as a victim machine for simulating an actual attack and capturing traffic in the process. Here, we are using a Windows 11 VM as the victim machine while an Ubuntu Server 22.04.1 VM is used as the attacker VM, with the hypervisor being VMWare Workstation Pro.

<img width="1470" alt="Pasted Graphic" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/092551ea-76a7-4b62-bacb-8e00433bfb0e">

**<h3>Step 1: Setting up the VMs</h3>** 

**<h4>1A. Ubuntu Server VM:</h4>**

In the first step, we set up the Ubuntu Server VM such that it has a static IP address and can be easily accessed from the host system. In VMWare Workstation Pro, going to Edit-> Virtual Network Editor, we can figure out the Subnet and Gateway IP of the Ubuntu VM. 

![External Connection](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/4cab390a-0b90-452f-99d3-54e7d2eab787)

![NAT Settings](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/ffafc601-ce07-43c0-86d8-fdcb130485e9)

We then enter this information into the Subnet and Gateway fields into the VM’s data fields, with a hostname of 8.8.8.8 to ensure that this VM has a static IP address. We also install OpenSSH so that the host client can connect to the VM remotely, making copy/paste operations easier. 

![f6d1e3b7-9dfc-4d70-b40b-76d700f5496b_926x264](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/5763041b-78fc-4d91-a1e8-8d775d4bcb7e)

Pinging 8.8.8.8 with the Ubuntu VM, we can see that it has been successfully configured to work with external networks. 

<img width="423" alt="user@attackoptsliver$ ping -c 2 8 8 8 8" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/48c27d7a-00b1-4419-aea4-6cc32a1b5519">

This indicates that the VM is now ready to perform the required operations.

**<h4>1B. Windows VM:</h4>** 

We will be using a Windows 11 VM with all the defenses turned off so that Microsoft Defender does not interfere in the operations we will be performing. 

**<h5>A. Disabling Tamper Protection:</h5>** 
   Tamper protection helps protect certain security settings, such as virus and threat protection, from being disabled or changed. We turn this off along with the other settings in the Virus and Threat Protection settings in Windows Defender. 

   ![image](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/15b61bbc-3734-4320-8ea2-ae7f2e1688a2)


   **<h5>B. Local Group Policy Editor:</h5>** 
    The Local Group Policy Editor (or gpedit. msc) is a system utility that allows you to view and edit group policy settings on your computer. This tool can be further used to configure advanced system settings that aren't available in the standard Settings app or Control Panel. Going to Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus, we can enable “Turn Off Microsoft Defender Antivirus”, which prevents Defender from running and checking for any malware or PUP (Potentially Unwanted Programs).


<img width="1143" alt="Pasted Graphic 2" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/da2a759e-bf5d-45da-bb14-324149dbb7f7">


  C. Additionally, we also run the command “REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f”, which adds a value to the Windows Registry in Local Machine that sets the value of Anti-Spyware to 1, disabling Defender’s anti-spyware component. This is essential for us, as we prefer to use a different security solution and wants to ensure that Windows Defender does not interfere. 
 
**<h3>Step 2:  Setup Defense Systems for Logging and Collection</h3>**

**<h5>2A. Installing Sysmon:</h5>**
	System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time. Using the following set of commands, we can correctly install and then configure Sysmon on the Windows VM. 


```
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml
```
The aforementioned commands are responsible for downloading and installing Sysmon on the Windows VM. We also include an additional configuration script for it, which functions as a starting point for system change monitoring in a self-contained and accessible package. This configuration and results also give us an idea of what is possible for Sysmon.

We then run the following two commands, which check if the Sysmon service is up and running while checking for any logged events to see if the service is working as intended.

```
Get-Service sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

![PS C UsersUserDownloadsSysmon Get-Service sysmon64](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/e3ca8836-d3c7-4df0-879d-aa9f9294cea7)
<img width="639" alt="Pasted Graphic 3" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/fc2ed2ed-5370-49fd-883d-14bdc84fd0e9">

**<h3>2B. Creating a LimaCharlie sensor:</h3>**

Limacharlie is an Endpoint Detection and Response (EDR) solution, offering continuous and unparalleled visibility into desktop, server, and cloud endpoints. It excels in monitoring both behavioral and technical aspects, with a telemetry retention period of 1 year. In this lab, we will use LimaCharlie as our primary source of collection for the Sysmon logs and analysis of said logs. 

After creating a LimaCharlie account, we then move on to the process of creating a sensor for having a centralized platform for collection and analysis of data. The first step is to create a sensor on the platform for Windows 11.

<img width="879" alt=" Select the installer for your architecture" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/fe2ecf58-8d58-4a8c-93fd-4f62aae5ddd2">

We then use the download link with the command line argument to install the sensor into an executable file into our local directory.

![f821e410-d4d3-4161-a426-9d8ff348806c_610x392](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/db997877-4423-4137-a9cd-25e013a8be36)

This screen marks the successful installation of the sensor, which can then be viewed in the actual LimaCharlie cloud platform, where we can see that the sensor is active and running while receiving logs from the system on which it is installed on.

<img width="981" alt="Pasted Graphic 5" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/f763c27e-d646-4180-aaa6-2762494840dc">

**<h3>2C. Setting up the Attack VM using Sliver:</h3>**

Sliver is a command and control (C2) framework designed to provide advanced capabilities for covertly managing and controlling remote systems. This tool can be used to set up a secure and reliable communication channel over Mutual TLS, HTTP(S), DNS, or Wireguard with target machines, enabling them to execute commands, gather information, and perform various post-exploitation activities.

This can be done locally or through SSH, using the OpenSSH server we installed earlier, connecting to the Ubuntu VM using the command ssh user@192.168.78.128.


```
sudo apt install -y mingw-w64
wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server
sudo chmod +x /usr/local/bin/sliver-server
mkdir -p /opt/sliver
```

The commands written above can be executed in order to first install Mingw64 for dependencies, then we use wget to download and install the sliver-server binary, which allows us to run a server on this VM. Finally, we create a working local directory for the server. 






