
# **Cyber Security Internship – Task 2: SECURITY ALERT MONITORING & INCIDENT RESPONSE**
# **Log Analysis using Splunk**

## **Objective**
The purpose of this task is to analyze a given set of security logs using **Splunk**.  
The analysis involves:
- Detecting suspicious activities.  
- Identifying malware-related events.  
- Tracking login successes and failures.  
- Extracting insights from connection attempts and file accesses.  
- Generating reports and visualizations.

This README documents **all the steps followed**, including:
- Setting up Splunk.  
- Uploading logs.  
- Performing searches using SPL queries.  
- Taking screenshots for documentation.  
- Final observations and reports.

---

## **Tools & Environment**
| Tool/Software        | Version/Details           |
|----------------------|---------------------------|
| **Operating System** | Windows 11 Home           |
| **Splunk**           | Splunk Enterprise (Free Trial) |
| **Log File**         | `SOC_Task2_Sample_Logs.txt` |
| **Index Used**       | `main`                    |
| **Source Type**      | `future-interns-01`       |

---

## **Initial Setup**
1. Installed **Splunk Enterprise**.
2. Created a new index named `main`.
3. Uploaded the log file:
   - Input type → *Uploaded File*
   - File name → `SOC_Task2_Sample_Logs.txt`
   - Source type → `future-interns-01`
   - Host → `Dakshu`
   - Index → `main`
4. Verified that Splunk indexed the events successfully.


<img width="3200" height="2000" alt="file-upload-splunk" src="https://github.com/user-attachments/assets/5fe7d323-7d8c-47ac-a722-53b4c1301b5f" />

<img width="1609" height="1159" alt="File-credentials-splunk" src="https://github.com/user-attachments/assets/76e6e4b8-828c-463f-9971-d4fe836b7880" />

---

## **Basic Searches**

### 1. Display first 5 logs
```spl
index=main sourcetype="future-interns-01"
| head 5
```
**Purpose:**  
Shows the first 5 events in the dataset.
By default splunk sorts based on the timestamp.

<img width="3200" height="2000" alt="Top5-s2" src="https://github.com/user-attachments/assets/c7ed7992-548e-4fcb-9b65-62b532798979" />
---
### 2. Display first 10 logs in a table
```spl
index=main sourcetype="future-interns-01"
| table _time user ip action
| head 10
```
**Purpose:**  
Displays key fields (`_time`, `user`, `ip`, `action`) in table format for easy reading.

---

### 3. Total number of logs
```spl
index=main sourcetype="future-interns-01"
| stats count as Total_Events
```
**Purpose:**  
Gives a quick count of total events processed by Splunk.

<img width="3200" height="1200" alt="Total-events-s1" src="https://github.com/user-attachments/assets/5e212fb3-fe86-4264-809a-22496d2cf3bc" />

---

## **Login Analysis**

### 4. Show all logins( success and failure events )
```spl
index=main sourcetype="future-interns-01" ("login success" OR "login failed")
```
**Purpose:**  
Filters logs to only show login events, whether successful or failed.

---

### 5. Total logins, success, and failure in one table
```spl
index=main sourcetype="future-interns-01"
| eval status=if(searchmatch("login success"),"Successful","Failed")
| stats count as Total_Logins 
        count(eval(status="login success")) as Successful_Logins 
        count(eval(status="login failed")) as Failed_Logins
```
**Purpose:**  
Displays total logins, successful logins, and failed logins side-by-side.
<img width="3200" height="1360" alt="logins-success-failed" src="https://github.com/user-attachments/assets/437558ab-80f7-47f4-99a5-26062845974c" />

---

## **IP and User-Based Analysis**

### 6. Count events by IP address
```spl
index=main sourcetype="future-interns-01"
| stats count by ip
| sort - count
```
**Purpose:**  
Shows which IPs are most active.

---

### 7. Top 20 most active IPs
```spl
index=main sourcetype="future-interns-01"
| stats count by ip
| sort - count
| head 20
```
**Purpose:**  
Finds the top 20 IPs generating the most events.

---

### 8. Count events by username
```spl
index=main sourcetype="future-interns-01"
| stats count by user
| sort - count
```
**Purpose:**  
Shows which users are most active.

---

## **Malware Detection Analysis**

### 9. Display only malware detection logs
```spl
index=main sourcetype="future-interns-01" "malware detected"
| table -time user ip threat
| sort _time
```
**Purpose:**  
Filters logs to only malware-related activity.
<img width="3200" height="2000" alt="all-malware-events-s5" src="https://github.com/user-attachments/assets/418a1c4d-22ef-4ac3-959a-a75ab8e4b992" />

---

### 10. Count malware events by IP
```spl
index=main sourcetype="future-interns-01" "malware detected"
| stats count by ip
| sort - count
| head 10

```
**Purpose:**  
Identifies which IPs are most frequently associated with malware.

<img width="3200" height="1648" alt="Malware-infected-ips-s6" src="https://github.com/user-attachments/assets/02350bdd-cee9-478b-a097-270e610ff79f" />

---

### 11. Malware vs Login Failures by IP
```spl
index=main sourcetype="future-interns-01"
| eval malware_event=if(searchmatch="malware detected",1,0)
| eval login_fail_event=if(searchmatch="login failed",1,0)
| stats sum(malware_event) as Total_Malware,
        sum(login_fail_event) as Total_Login_Failures by ip
| sort - Total_Malware
```
**Purpose:**  
Shows how many malware detections and login failures occurred per IP.
<img width="3200" height="2000" alt="Correlate-Malware-with-Login-Failures" src="https://github.com/user-attachments/assets/f4bb4ca6-5cd4-4cc9-93ac-75d8134a3ddf" />

---

### 12. Threats grouped by type
```spl
index=main sourcetype="future-interns-01"
| eval ThreatType=case(
    searchmatch="malware detected","Malware",
    searchmatch="login failed","Failed Login",
    searchmatch="login success","Successful Login",
    searchmatch="file accessed","File Activity",
    searchmatch="connection attempt","Connection Attempt",
    true(),"Other")
| stats count by ThreatType
| sort - count
```
**Purpose:**  
Categorizes and counts threats by their type.
<img width="3200" height="2000" alt="Threat-summary" src="https://github.com/user-attachments/assets/e9c73045-1e5d-4be8-a46f-7f081e76c29d" />
---

## **Advanced Searches**

### 13. Top 5 malware-affected IPs
```spl
index=main sourcetype="future-interns-01" "malware detected"
| stats count by ip
| sort - count
| head 5
```
**Purpose:**  
Highlights the most suspicious IPs with malware detections.

---

### 14. Timeline of all events
```spl
index=main sourcetype="future-interns-01"
| timechart span=30m count by action
```
**Purpose:**  
Visualizes failed login attempts over time.
<img width="3200" height="2000" alt="Timeline-of-all-events" src="https://github.com/user-attachments/assets/c12e4268-611a-4f09-bebe-d8380b35531c" />

---
### 

---
#### 15. Unique IP Count**
**SPL Query:**

```spl
index=main sourcetype="future-interns-01"
| stats dc(ip) as Unique_IPs
```
**Purpose:**
This query counts the **total number of unique IP addresses** present in the logs.
It’s useful for understanding how many distinct systems interacted with the network.

**Result:**
Displays a single number representing unique IPs.

**Screenshot Reference:**
<img width="3200" height="1080" alt="Unique-ips-s3" src="https://github.com/user-attachments/assets/0da2f9af-75d7-43a9-a102-60ac6ead820f" />

### **📊 Dashboards and Visualizations**
### 1. Threats with percentage
```spl
index=main sourcetype="future-interns-01"
| eval ThreatType=case(
    searchmatch="malware detected","Malware",
    searchmatch="login failed","Failed Login",
    searchmatch="login success","Successful Login",
    searchmatch="file accessed","File Activity",
    searchmatch="connection attempt","Connection Attempt",
    true(),"Other")
| eventstats count as TotalEvents
| stats count as EventCount by ThreatType
| eval Percentage=round((EventCount/TotalEvents)*100,2)
| sort - EventCount
```
**Purpose:**  
Displays total count and percentage of each threat type.
<img width="3200" height="2000" alt="threatSummary-pieChart" src="https://github.com/user-attachments/assets/0a9d7eb5-5e7c-4122-a058-961d229acdf4" />

---
#### 2. Top IPs with Malware Events (Column Chart)**
**SPL Query:**

```spl
index=main sourcetype="future-interns-01" "malware detected"
| stats count by ip
| sort - count
| head 10
```
**Purpose:**
This visualization helps to quickly identify which IP addresses are most frequently associated with malware detections.
It assists in focusing investigations on potentially compromised hosts or external attackers.
**Visualization Used:**

* **Chart Type:** Column Chart
* **Field on X-axis:** `ip`
* **Field on Y-axis:** `count`

**Screenshot Reference:**
<img width="3200" height="2000" alt="top-ips-with-malwares-columnChart" src="https://github.com/user-attachments/assets/52c6c344-956f-4af8-a094-c357abb13d27" />

---

#### 3. Login Attempts Trend Over Time (Line Chart)**

```spl
index=main sourcetype="future-interns-01" ("login success" OR "login failed")
| timechart span=30m count(eval(searchmatch("login success"))) as Successful_Logins,
    count(eval(searchmatch("login failed"))) as Failed_Logins
| fields _time Successful_Logins Failed_Logins
```

**Purpose:**
This chart displays login successes and failures over time, helping SOC analysts identify unusual login patterns such as brute-force attempts or unusual spikes in activity.
**Visualization Used:**

* **Chart Type:** Line Chart
* **Field for X-axis:** `_time`
* **Fields for Y-axis:** `Successful_Logins` and `Failed_Logins`

**Screenshot Reference:**

<img width="3200" height="2000" alt="logins-lineChart" src="https://github.com/user-attachments/assets/b6f0ee6a-a281-4b49-90a0-2269b7da6c18" />

---


### **📝 Adding Field Extractions**

**Purpose:**
Field extractions allow Splunk to automatically recognize and separate different parts of raw log data, such as `user`, `ip`, `action`, and `threat`.
This makes search and analysis much easier.

**Steps to Create Field Extractions:**

1. Go to **Settings > Fields > Field Extractions** in Splunk.
2. Click **New Field Extraction** and select:

   * **App:** `Search & Reporting`
   * **Name:** `FutureInterns-Extraction`
3. In the **Sample Event**, highlight important values like:

   * `user=bob`
   * `ip=172.16.0.3`
   * `action=malware detected`
   * `threat=Ransomware Behavior`
4. Splunk will automatically generate regex patterns for each field.
5. Save and apply the extraction.

**Example Screenshot Reference:**
`Adding-extractions.png`

---

This content will perfectly integrate into your README. It documents both **queries** and **dashboards** along with **purpose and visual references**.

<img width="3200" height="2000" alt="Adding-extractions" src="https://github.com/user-attachments/assets/2f943dce-1466-434c-b584-c115f53bc531" />

## **Final Findings**
- Total logs analyzed: 50  
- Total malware detections: 11
- Most common threat type: Trojan Detected  
- IP with highest malicious activity: 203.0.113.77  
- Total failed logins: 5
- Total successful logins: 11

---

## **Deliverables**
| File Name              | Description                  |
|-----------------------|------------------------------|
| `README.md`           | Complete documentation        |
| `SOC_Task2_Sample_Logs.txt` | Log file provided          |
| `Screenshots/`        | Folder containing screenshots |
| `Splunk_Report.html`  | Final generated report        |

---

## **Author**
- **Name:** Dakshayani Sindiri  
- **GitHub:** [dakshayanisindiri-98](https://github.com/dakshayanisindiri-98)  
- **LinkedIn:** *(https://www.linkedin.com/in/dakshayani-sindiri-a55037302)*  
