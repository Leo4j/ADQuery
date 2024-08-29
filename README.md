# ADQuery

This script is meant to help with enumeration of GPOs, OUs they apply to, principals within those OUs, Groups and Group Membership, and Foreign Security Principals. Single User and Computer objects can be enumerated too

## Load in memory
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/ADQuery/main/ADQuery.ps1')
```

## Enumerate for GPOs
```
ADQuery -GPOs
```
```
ADQuery -GPOName "Computer - LAPS"
```
![image](https://github.com/user-attachments/assets/a0a818a6-aed4-475b-a09c-12d7ae9aef3e)

![image](https://github.com/user-attachments/assets/c64cd35d-e902-4238-9607-f5b0cdda6fb9)



## Enumerate for OUs
```
ADQuery -OUs
```
```
ADQuery -OUName "AllComputers"
```
```
ADQuery -OUDistName "OU=AllComputers,DC=ferrari,DC=local"
```
![image](https://github.com/user-attachments/assets/7676b319-626e-450d-8342-5786eb4822f4)

![image](https://github.com/user-attachments/assets/486b3c74-9f86-49e4-87b9-c5758a93cb99)


## Enumerate for Groups
```
ADQuery -Groups
```
```
ADQuery -GroupName "Domain Admins"
```
![image](https://github.com/user-attachments/assets/a9230dd1-7d1e-41e1-9c31-9bc711f7ccc2)

![image](https://github.com/user-attachments/assets/692a4668-1a3f-4e62-87bc-b3eb7eb25966)


## Enumerate for a User Object
```
ADQuery -UserName tomcat
```
![image](https://github.com/user-attachments/assets/144e95c0-c32d-41db-92d2-4bd125b52faa)


## Enumerate for a Computer Object
```
ADQuery -ComputerName CA01$
```
![image](https://github.com/user-attachments/assets/5f222d14-6f3e-42a3-a708-d812a1b32b7b)


## Enumerate for Foreign Security Principals
```
ADQuery -ForeignPrincipals
```
![image](https://github.com/user-attachments/assets/28519160-c056-4a21-a5eb-afe7daae8603)

## Convert SID to Principal
```
ADQuery -ConvertSID "S-1-5-21-2741628602-1183230269-2439862772-1605"
```
![image](https://github.com/user-attachments/assets/e2e14ef3-f3a1-46e8-8d99-c48607895f6d)
