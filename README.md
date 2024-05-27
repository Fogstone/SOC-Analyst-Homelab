This is a report based on a homelab created using LimaCharlie EDR with Sysmon and VMWare for lab containers.

**Initial Setup:**

This lab involves the use of two virtual machines: one serving as an attack machine while the other is used as a victim machine for simulating an actual attack and capturing traffic in the process. Here, we are using a Windows 11 VM as the victim machine while an Ubuntu Server 22.04.1 VM is used as the attacker VM, with the hypervisor being VMWare Workstation Pro.

<img width="1470" alt="Pasted Graphic" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/092551ea-76a7-4b62-bacb-8e00433bfb0e">

Step 1: Setting up the VMs 

1A. Ubuntu Server VM:

In the first step, we set up the Ubuntu Server VM such that it has a static IP address and can be easily accessed from the host system. In VMWare Workstation Pro, going to Edit-> Virtual Network Editor, we can figure out the Subnet and Gateway IP of the Ubuntu VM. 

![External Connection](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/4cab390a-0b90-452f-99d3-54e7d2eab787)

![NAT Settings](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/ffafc601-ce07-43c0-86d8-fdcb130485e9)

We then enter this information into the Subnet and Gateway fields into the VM’s data fields, with a hostname of 8.8.8.8 to ensure that this VM has a static IP address. We also install OpenSSH so that the host client can connect to the VM remotely, making copy/paste operations easier. 

![f6d1e3b7-9dfc-4d70-b40b-76d700f5496b_926x264](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/5763041b-78fc-4d91-a1e8-8d775d4bcb7e)

Pinging 8.8.8.8 with the Ubuntu VM, we can see that it has been successfully configured to work with external networks. 

<img width="423" alt="user@attackoptsliver$ ping -c 2 8 8 8 8" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/48c27d7a-00b1-4419-aea4-6cc32a1b5519">

This indicates that the VM is now ready to perform the required operations.

1B. Windows VM: 

We will be using a Windows 11 VM with all the defenses turned off so that Microsoft Defender does not interfere in the operations we will be performing. 

	A. Disabling Tamper Protection: 
   Tamper protection helps protect certain security settings, such as virus and threat protection, from being disabled or changed. We turn this off along with the other settings in the Virus and Threat Protection settings in Windows Defender. 

   ![image](https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/15b61bbc-3734-4320-8ea2-ae7f2e1688a2)


   B. Local Group Policy Editor: The Local Group Policy Editor (or gpedit. msc) is a system utility that allows you to view and edit group policy settings on your computer. This tool can be further used to configure advanced system settings that aren't available in the standard Settings app or Control Panel. Going to Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus, we can enable “Turn Off Microsoft Defender Antivirus”, which prevents Defender from running and checking for any malware or PUP (Potentially Unwanted Programs).


<img width="1143" alt="Pasted Graphic 2" src="https://github.com/Fogstone/SOC-Analyst-Homelab/assets/51188893/da2a759e-bf5d-45da-bb14-324149dbb7f7">


  C. Additionally, we also run the command “REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f”, which adds a value to the Windows Registry in Local Machine that sets the value of Anti-Spyware to 1, disabling Defender’s anti-spyware component. This is essential for us, as we prefer to use a different security solution and wants to ensure that Windows Defender does not interfere. 
 

 

￼
