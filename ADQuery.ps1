function ADQuery {
	
	<#
    .SYNOPSIS
    ADQuery | Author: Rob LP (@L3o4j)
    https://github.com/Leo4j/ADQuery

    .DESCRIPTION
    Query Active Directory
    #>
	
	param (
        [string]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,
        [string]$Server = $null,
        [string]$UserName,
		[string]$ComputerName,
		[string]$GPOName,
		[string]$OUName,
		[string]$OUDistName,
		[string]$GroupName,
		[string]$ConvertSID,
		[switch]$GPOs,
		[switch]$OUs,
		[switch]$Groups,
		[switch]$Debugging,
		[switch]$ForeignPrincipals
    )
	
	if(!$Debugging){
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	# Set the process priority to High
	$currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
	$currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High
	
	Set-Variable MaximumHistoryCount 32767
	
	if($GPOs){
		$TempDomainGPOs = @()
		$TotalScrapedOUs = @()
		$TempAllDomainOUs = @()
		$TempAllCollDomainOUs = @()
		$DomainGPOs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect GPOs -Property gpcfilesyspath,displayname)
		$AllCollectedOUs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect OUs -Property gplink,name,distinguishedname)
		
		foreach ($DomainGPO in $DomainGPOs) {
			$GPOGuid = ($DomainGPO.gpcfilesyspath -split "}")[-2].split("{")[-1]  # Extracting the GPO's GUID
			$TargetOUs = @($AllCollectedOUs | Where-Object {$_.gplink -like "*$GPOGuid*"} )
			$TotalScrapedOUs += @($TargetOUs)
			$ScrapeOUs = $TargetOUs.name -Join " - "
			$TempDomainGPOs += [PSCustomObject]@{
				"GPO Name" = $DomainGPO.DisplayName
				"Path" = $GPOGuid
				"OUs the policy applies to" = $ScrapeOUs
				#Domain = $Domain
			}
		}

  		if ($TempDomainGPOs) {
			$TempDomainGPOs | Sort-Object "GPO Name" | Format-Table -AutoSize -Wrap
		}
		
		foreach ($CollectOU in $TotalScrapedOUs) {
			foreach ($DomainGPO in $DomainGPOs) {
				$GPOGuid = ($DomainGPO.gpcfilesyspath -split "}")[-2].split("{")[-1]  # Extracting the GPO's GUID
				if($CollectOU.gplink -like "*$GPOGuid*"){
					$TempAllDomainOUs += [PSCustomObject]@{
						"Collected OUs"    = $CollectOU.name
						"Distinguished Name" = $CollectOU.distinguishedname
						#Domain  = $domain
						"GPO Membership" = $DomainGPO.DisplayName
					}
				}
			}
		}
		
		if($TempAllDomainOUs) {
			$TempAllDomainOUs | Sort-Object -Unique "Collected OUs","Distinguished Name" | Format-Table -AutoSize -Wrap
		}
	}
	
	elseif($GPOName){
		$TempDomainGPOs = @()
		$TotalScrapedOUs = @()
		$TempAllDomainOUs = @()
		$TempAllCollDomainOUs = @()
		$DomainGPOs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect GPOs -Property gpcfilesyspath,displayname -LDAP "displayname=$GPOName")
		$AllCollectedOUs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect OUs -Property gplink,name,distinguishedname)
		$TotalEnabledUsers = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Users -Enabled -Property distinguishedName,samaccountname)
		$TotalEnabledMachines = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Computers -Enabled -Property distinguishedName,samaccountname)
		$TotalGroups = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Groups -Property distinguishedName,samaccountname)
		$AllForeignSecurityPrincipals = @(Collect-ADObjects -Domain $Domain -Server $Server -LDAP "(&(objectCategory=foreignSecurityPrincipal)(CN=S-1-5-21*))")
		foreach ($DomainGPO in $DomainGPOs) {
			$GPOGuid = ($DomainGPO.gpcfilesyspath -split "}")[-2].split("{")[-1]  # Extracting the GPO's GUID
			$TargetOUs = @($AllCollectedOUs | Where-Object {$_.gplink -like "*$GPOGuid*"} )
			$TotalScrapedOUs += @($TargetOUs)
			$ScrapeOUs = $TargetOUs.name -Join " - "
			$TempDomainGPOs += [PSCustomObject]@{
				"GPO Name" = $DomainGPO.DisplayName
				"Path" = $GPOGuid
				"OUs the policy applies to" = $ScrapeOUs
				#Domain = $Domain
			}
		}

  		if ($TempDomainGPOs) {
			$TempDomainGPOs | Sort-Object "GPO Name" | Format-Table -AutoSize -Wrap
		}
		
		foreach ($CollectOU in $TotalScrapedOUs) {
				
			$ouDN = $CollectOU.distinguishedName
			#$domain = $CollectOU.domain
			
			# Filter users within this OU
			$users = @($TotalEnabledUsers | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname })

			# Filter computers within this OU
			$computers = @($TotalEnabledMachines | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname })
			
			# Filter groups within this OU
			$collgroups = @($TotalGroups | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname + "(Grp)"})
			
			# Filter orgunits within this OU
			$collOUs = @($AllCollectedOUs | Where-Object { $_.distinguishedName -like "*,${ouDN}" })
			$orgunits = @($collOUs | ForEach-Object { $_.name + "(OU)" })
			
			# Filter foreign principals within this OU
    		$collforeign = @($AllForeignSecurityPrincipals | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.name + "(Foreign)" })

			# Combine users and computers
			$members = @($users + $computers + $collgroups + $orgunits + $collforeign) -join ' - '

			# Create a custom object for each OU with its members
			$TempAllDomainOUs += [PSCustomObject]@{
				"Collected OUs"    = $CollectOU.name
				"Distinguished Name" = $CollectOU.distinguishedname
				Members = $members
			}
			
			if($collOUs){
				foreach($collOU in $collOUs){
					$TempAllCollDomainOUs += [PSCustomObject]@{
						"Member OU"    = $collOU.name
						"Distinguished Name" = $collOU.distinguishedname
						"OU Membership" = $CollectOU.distinguishedName
					}
				}
			}
		}
		
		if($TempAllDomainOUs) {
			$TempAllDomainOUs | Sort-Object "Collected OUs" | Format-Table -AutoSize -Wrap
		}
		
		if($TempAllCollDomainOUs) {
			$TempAllCollDomainOUs | Sort-Object -Unique "OU Name","Distinguished Name" | Format-Table -AutoSize -Wrap
		}
	}
	
	elseif($OUs){
		$TempAllDomainOUs = @()
		$AllCollectedOUs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect OUs -Property gplink,name,distinguishedname)
		
		foreach ($CollectOU in $AllCollectedOUs) {

			# Create a custom object for each OU with its members
			$TempAllDomainOUs += [PSCustomObject]@{
				"OU Name"    = $CollectOU.name
				"Distinguished Name" = $CollectOU.distinguishedname
			}
		}
		
		if($TempAllDomainOUs) {
			$TempAllDomainOUs | Sort-Object "OU Name" | Format-Table -AutoSize -Wrap
		}
	}
	
	elseif($OUName){
		$TempAllDomainOUs = @()
		$TempAllCollDomainOUs = @()
		$AllCollectedOUs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect OUs -Property gplink,name,distinguishedname)
		$SelectedOUs = @($AllCollectedOUs | Where-Object {$_.name -eq $OUName} )
		$TotalEnabledUsers = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Users -Enabled -Property distinguishedName,samaccountname)
		$TotalEnabledMachines = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Computers -Enabled -Property distinguishedName,samaccountname)
		$TotalGroups = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Groups -Property distinguishedName,samaccountname)
		$AllForeignSecurityPrincipals = @(Collect-ADObjects -Domain $Domain -Server $Server -LDAP "(&(objectCategory=foreignSecurityPrincipal)(CN=S-1-5-21*))")
		
		foreach($SelectedOU in $SelectedOUs){
			
			$members = $null
			
			$ouDN = $SelectedOU.distinguishedName
			#$domain = $SelectedOU.domain
			
			# Filter users within this OU
			$users = @($TotalEnabledUsers | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname })

			# Filter computers within this OU
			$computers = @($TotalEnabledMachines | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname })
			
			# Filter groups within this OU
			$collgroups = @($TotalGroups | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname + "(Grp)"})
			
			# Filter orgunits within this OU
			$collOUs = @($AllCollectedOUs | Where-Object { $_.distinguishedName -like "*,${ouDN}" })
			$orgunits = @($collOUs | ForEach-Object { $_.name + "(OU)" })
			
			# Filter foreign principals within this OU
			$collforeign = @($AllForeignSecurityPrincipals | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.name + "(Foreign)" })

			# Combine users and computers
			$members = @($users + $computers + $collgroups + $orgunits + $collforeign) -join ' - '

			# Create a custom object for each OU with its members
			$TempAllDomainOUs += [PSCustomObject]@{
				"OU Name"    = $SelectedOU.name
				"Distinguished Name" = $SelectedOU.distinguishedname
				#Domain  = $domain
				Members = $members
			}
			
			if($collOUs){
				foreach($collOU in $collOUs){
					$TempAllCollDomainOUs += [PSCustomObject]@{
						"Member OU"    = $collOU.name
						"Distinguished Name" = $collOU.distinguishedname
						"OU Membership" = $SelectedOU.distinguishedName
					}
				}
			}
		}
		
		if($TempAllDomainOUs) {
			$TempAllDomainOUs | Sort-Object "OU Name" | Format-Table -AutoSize -Wrap
		}
		
		if($TempAllCollDomainOUs) {
			$TempAllCollDomainOUs | Sort-Object -Unique "OU Name","Distinguished Name" | Format-Table -AutoSize -Wrap
		}
	}
	
	elseif($OUDistName){
		$TempAllDomainOUs = @()
		$TempAllCollDomainOUs = @()
		$AllCollectedOUs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect OUs -Property gplink,name,distinguishedname)
		$SelectedOU = @($AllCollectedOUs | Where-Object {$_.distinguishedname -eq $OUDistName} )
		$TotalEnabledUsers = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Users -Enabled -Property distinguishedName,samaccountname)
		$TotalEnabledMachines = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Computers -Enabled -Property distinguishedName,samaccountname)
		$TotalGroups = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Groups -Property distinguishedName,samaccountname)
		$AllForeignSecurityPrincipals = @(Collect-ADObjects -Domain $Domain -Server $Server -LDAP "(&(objectCategory=foreignSecurityPrincipal)(CN=S-1-5-21*))")
		
		$ouDN = $SelectedOU.distinguishedName
		#$domain = $SelectedOU.domain
		
		# Filter users within this OU
		$users = @($TotalEnabledUsers | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname })

		# Filter computers within this OU
		$computers = @($TotalEnabledMachines | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname })
		
		# Filter groups within this OU
		$collgroups = @($TotalGroups | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.samaccountname + "(Grp)"})
		
		# Filter orgunits within this OU
		$collOUs = @($AllCollectedOUs | Where-Object { $_.distinguishedName -like "*,${ouDN}" })
		$orgunits = @($collOUs | ForEach-Object { $_.name + "(OU)" })
		
		# Filter foreign principals within this OU
		$collforeign = @($AllForeignSecurityPrincipals | Where-Object { $_.distinguishedName -like "*,${ouDN}" } | ForEach-Object { $_.name + "(Foreign)" })

		# Combine users and computers
		$members = @($users + $computers + $collgroups + $orgunits + $collforeign) -join ' - '

		# Create a custom object for each OU with its members
		$TempAllDomainOUs += [PSCustomObject]@{
			"OU Name"    = $SelectedOU.name
			"Distinguished Name" = $SelectedOU.distinguishedname
			#Domain  = $domain
			Members = $members
		}
		
		if($TempAllDomainOUs) {
			$TempAllDomainOUs | Sort-Object "OU Name" | Format-Table -AutoSize -Wrap
		}
		
		if($collOUs){
			foreach($collOU in $collOUs){
				$TempAllCollDomainOUs += [PSCustomObject]@{
					"Member OU"    = $collOU.name
					"Distinguished Name" = $collOU.distinguishedname
					"OU Membership" = $SelectedOU.distinguishedName
				}
			}
			$TempAllCollDomainOUs | Sort-Object -Unique "OU Name","Distinguished Name" | Format-Table -AutoSize -Wrap
		}
	}
	
	elseif($Groups){
		$TotalGroups = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect Groups -Convert -Property samaccountname,objectsid,description)
		$TempOtherGroups = @()
		
		foreach($OtherGroup in $TotalGroups){
			$TempOtherGroups += [PSCustomObject]@{
				"Group Name" = $OtherGroup.SamAccountName
				"SID" = $OtherGroup.objectsid
				"Description" = $OtherGroup.description
			}
		}
		
		$TempOtherGroups | Where-Object {$_."Group Name"} | Sort-Object "Group Name" | Format-Table -AutoSize -Wrap
	}
	
	elseif($GroupName){
		function Get-NestedGroupMembers {
			param (
				[string]$GroupName,
				[string]$Domain,
				[string]$Server,
				[ref]$AllMembers
			)

			$TargetGroup = @(Collect-ADObjects -Domain $Domain -Server $Server -Property name,member,distinguishedName,samaccountname,memberof,objectClass,objectCategory,objectsid -Convert -LDAP "(&(samaccountname=$GroupName)(objectCategory=group))")
			if(!$TargetGroup) {
				Write-Output "[-] Group not found"
				Write-Output ""
				return
			}

			$ExtractedRawMembers = @($TargetGroup | Select-Object -ExpandProperty member)
			$ExtractedMembers = @()

			foreach($ExtractedRawMember in $ExtractedRawMembers) {
				$Member = ($ExtractedRawMember -split ",")[0] -replace "CN=",""
				if (-not ($AllMembers.Value -contains $Member)) {
					$AllMembers.Value += $Member
				}
				$ExtractedMembers += $Member
			}

			foreach($ExtractedMember in $ExtractedMembers) {
				$NestedGroups = @(Collect-ADObjects -Domain $Domain -Server $Server -Property name,member,distinguishedName,samaccountname,memberof,objectClass,objectCategory,objectsid -Convert -LDAP "(&(samaccountname=$ExtractedMember)(objectCategory=group))")
				foreach($nested in $NestedGroups) {
					Get-NestedGroupMembers -GroupName $nested.samaccountname -Domain $Domain -Server $Server -AllMembers $AllMembers
				}
			}
		}

		# Initialise a collection to hold all members
		$AllMembers = @()
		$AllMembersRef = [ref]$AllMembers
		Get-NestedGroupMembers -GroupName $GroupName -Domain $Domain -Server $Server -AllMembers $AllMembersRef
		
		$TargetGroup = @(Collect-ADObjects -Domain $Domain -Server $Server -Property name,samaccountname,objectsid -Convert -LDAP "(&(samaccountname=$GroupName)(objectCategory=group))")

		$Result = [PSCustomObject]@{
			"Group Name" = $TargetGroup.samaccountname
			"SID" = $TargetGroup.objectsid
			"Members" = ($AllMembers | Sort-Object -Unique) -join ' - '
		}
		
		$Result | Format-Table -AutoSize -Wrap
	}
	
	elseif($UserName){
		if($UserName -like "*$"){
			Write-Output "[-] Use the following command for machine objects: ADQuery -ComputerName $UserName"
			Write-Output ""
			break
		}
		$ExtractUser = Collect-ADObjects -Domain $Domain -Server $Server -Identity $UserName -Convert
		if(!$ExtractUser){Write-Output "[-] Principal not found";Write-Output "";break}
		$inactiveThreshold = (Get-Date).AddMonths(-6)
		$DomainPolicy = Collect-ADObjects -Domain $Domain -Server $Server -Collect DomainPolicy -Property minPwdAge,maxPwdAge,pwdProperties,minPwdLength,pwdHistoryLength,lockoutThreshold,ms-ds-machineaccountquota
		$maxPasswordAge = $DomainPolicy.maxPwdAge
		$maxPwdAgeTimeSpan = [TimeSpan]::FromTicks($DomainPolicy.maxpwdage)
		$maxPwdAgeDays = -$maxPwdAgeTimeSpan.TotalDays
		$expirationDate = $ExtractUser.pwdlastset + $maxPwdAgeDays
		$uacValue = [int]$ExtractUser.userAccountControl
		$binaryUAC = [convert]::ToString($uacValue, 2).PadLeft(32, '0')
		$Result = $binaryUAC[-8] -eq '1'
		$GroupsMembership = @($ExtractUser | Select-Object -ExpandProperty memberof)
		$sumextract = @()
		$GatheredGPOs = @()
		
		$InfoTable = [PSCustomObject]@{
			"User Name" = $ExtractUser.name
			"Account active" = if ($ExtractUser.lastLogon -eq ""){""} elseif ($ExtractUser.lastLogon -ge $inactiveThreshold) { "True" } else { "False" }
			"Account expires"  = $ExtractUser.accountexpires
			"Password last set" = $ExtractUser.pwdlastset
			"Password expires" = if($ExtractUser.userAccountControl -band 0x10000){"Never"}else{"$($expirationDate.ToLocalTime())"}
			"Password required" = if($ExtractUser.userAccountControl -band 32){"False"}else{"True"}
			"Object SID" = $ExtractUser.objectsid
			"Object GUID" = $ExtractUser.objectguid
			"Mail" = $ExtractUser.mail
		}
		
		$MoreInfoTable = [PSCustomObject]@{
			"When Created" = $ExtractUser.whencreated
			"Last Logon" = $ExtractUser.lastlogontimestamp
			"Logon count" = $ExtractUser.logoncount
			"Bad pwd count" = $ExtractUser.badpwdcount
			"Bad Pass time" = $ExtractUser.badpasswordtime
		}
		
		$ScriptsTable = [PSCustomObject]@{
			"Workstations allowed" = if($ExtractUser.userworkstations){$ExtractUser.userworkstations}else{"All"}
			"Logon script" = $ExtractUser.scriptpath
			"User profile" = $ExtractUser.profilepath
			"Home directory" = $ExtractUser.homedirectory
			"Home drive" = $ExtractUser.homedrive
		}
		
		$ChecksTable = [PSCustomObject]@{
			"Admin Count" = if($ExtractUser.admincount -eq 1){"True"}else{"False"}
			"Fine-grained pol" = if($ExtractUser."msDS-ResultantPSO"){"True"}else{"False"}
			"Service Account" = if($ExtractUser.serviceprincipalname){"True"}else{"False"}
			"GMSA" = if($ExtractUser.objectClass -like "*GroupManagedServiceAccount*"){"True"}else{"False"}
			#"Can Read LAPS" = 
			"AS-REProastable" = if($ExtractUser.userAccountControl -band 0x00400000){"True"}else{"False"}
			"Protected" = if($ExtractUser.memberof -like "*Protected Users*"){"True"}else{"False"}
			"Sensitive" = if($ExtractUser.useraccountcontrol -band 1048576){"True"}else{"False"}
			#"Can DCSync" = 
			"User Password" = $ExtractUser.userpassword
			"Unix Passwords" = $ExtractUser.unixUserPassword
			"SIDHistory set" = if($ExtractUser.sidHistory){"True"}else{"False"}
			"Rev. Encryption" = $Result
		}
		
		foreach($entry in $GroupsMembership){
			$extract = ($entry -split ",")[0]
			$extract = ($extract -split "=")[1]
			$sumextract += $extract
		}
		
		$finalsumextract = ($sumextract | Sort-Object -Unique) -join ", "
		
		$GroupsTable = [PSCustomObject]@{
			"Groups" = $finalsumextract
		}
		
		$DomainGPOs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect GPOs -Property gpcfilesyspath,displayname -LDAP "displayname=$GPOName")
		
		$OUsMembership = @()
		$OUsMembershipList = $ExtractUser.distinguishedName
		$dnComponents = @($OUsMembershipList -split ',')
		$ouComponents = @(($dnComponents | Where-Object { $_ -like "OU=*" }) -replace "OU=","")
		$OUsTable = [PSCustomObject]@{
			"OUs" = $ouComponents -join ", "
		}
		
		foreach($ouComponent in $ouComponents){
			$ExtractBit = @(Collect-ADObjects -Domain $Domain -Server $Server -LDAP "ou=$ouComponent")
			$ExtractBit = $ExtractBit.gplink
			
			if ($ExtractBit) {
				# Split the gPLink string into individual GPO links
				$gpoLinks = $ExtractBit -split "\]"

				foreach ($gpoLink in $gpoLinks) {
					if ($gpoLink -ne "") {
						# Trim the leading "[" and apply the regex to extract the GUID
						if ($gpoLink.TrimStart("[") -match 'CN=\{([0-9A-Fa-f-]+)\},CN=Policies,CN=System,DC=') {
							$gpoGuid = $matches[1]

							# Collect GPO details using the GUID
							$GatherGPO = @(Collect-ADObjects -Domain $Domain -Server $Server -LDAP "cn={$gpoGuid}")

							# Assuming $GatheredGPOs is an array to hold all gathered GPOs
							$GatheredGPOs += $GatherGPO.displayname
						}
					}
				}
			}
		}
		
		$GPOsTable = [PSCustomObject]@{
			"GPOs" = $GatheredGPOs -join ", "
		}
		
		$InfoTable
		$MoreInfoTable
		$ScriptsTable
		$ChecksTable
		$GroupsTable
		$GPOsTable
		$OUsTable
	}
	
	elseif($ComputerName){
		if($ComputerName -notlike "*$"){
			Write-Output "[-] Make sure you add $ at the end of a computer name: ADQuery -ComputerName $ComputerName$"
			Write-Output ""
			break
		}
		$ExtractUser = Collect-ADObjects -Domain $Domain -Server $Server -Identity $ComputerName -Convert
		if(!$ExtractUser){Write-Output "[-] Principal not found";Write-Output "";break}
		$inactiveThreshold = (Get-Date).AddMonths(-6)
		$DomainPolicy = Collect-ADObjects -Domain $Domain -Server $Server -Collect DomainPolicy -Property minPwdAge,maxPwdAge,pwdProperties,minPwdLength,pwdHistoryLength,lockoutThreshold,ms-ds-machineaccountquota
		$maxPasswordAge = $DomainPolicy.maxPwdAge
		$maxPwdAgeTimeSpan = [TimeSpan]::FromTicks($DomainPolicy.maxpwdage)
		$maxPwdAgeDays = -$maxPwdAgeTimeSpan.TotalDays
		$expirationDate = $ExtractUser.pwdlastset + $maxPwdAgeDays
		$uacValue = [int]$ExtractUser.userAccountControl
		$binaryUAC = [convert]::ToString($uacValue, 2).PadLeft(32, '0')
		$Result = $binaryUAC[-8] -eq '1'
		$GroupsMembership = @($ExtractUser | Select-Object -ExpandProperty memberof)
		$sumextract = @()
		$GatheredGPOs = @()
		
		$InfoTable = [PSCustomObject]@{
			"Comp Name" = $ExtractUser.name
			"Operating System" = $ExtractUser.operatingsystem
			"IP Address" = (Resolve-DnsName -Name $ExtractUser.DnsHostName -Type A).IPAddress
			"Account active" = if ($ExtractUser.lastLogon -eq ""){""} elseif ($ExtractUser.lastLogon -ge $inactiveThreshold) { "True" } else { "False" }
			#"Account expires"  = $ExtractUser.accountexpires
			#"Password last set" = $ExtractUser.pwdlastset
			#"Password expires" = if($ExtractUser.userAccountControl -band 0x10000){"Never"}else{"$($expirationDate.ToLocalTime())"}
			"Password required" = if($ExtractUser.userAccountControl -band 32){"False"}else{"True"}
			"Object SID" = $ExtractUser.objectsid
			"Object GUID" = $ExtractUser.objectguid
			#"Mail" = $ExtractUser.mail
		}
		
		$MoreInfoTable = [PSCustomObject]@{
			"When Created" = $ExtractUser.whencreated
			"Last Logon" = $ExtractUser.lastlogontimestamp
			"Logon count" = $ExtractUser.logoncount
			"Bad pwd count" = $ExtractUser.badpwdcount
			"Bad Pass time" = $ExtractUser.badpasswordtime
		}
		
		$ChecksTable = [PSCustomObject]@{
			
			#"Fine-grained pol" = if($ExtractUser."msDS-ResultantPSO"){"True"}else{"False"}
			#"Service Account" = if($ExtractUser.serviceprincipalname){"True"}else{"False"}
			"Admin Count" = if($ExtractUser.admincount -eq 1){"True"}else{"False"}
			"GMSA" = if($ExtractUser.objectClass -like "*GroupManagedServiceAccount*"){"True"}else{"False"}
			#"Can Read LAPS" = 
			#"AS-REProastable" = if($ExtractUser.userAccountControl -band 0x00400000){"True"}else{"False"}
			#"Protected" = if($ExtractUser.memberof -like "*Protected Users*"){"True"}else{"False"}
			#"Sensitive" = if($ExtractUser.useraccountcontrol -band 1048576){"True"}else{"False"}
			#"Can DCSync" = 
			#"User Password" = $ExtractUser.userpassword
			#"Unix Passwords" = $ExtractUser.unixUserPassword
			"SIDHistory" = if($ExtractUser.sidHistory){"True"}else{"False"}
			#"Rev. Encryption" = $Result
		}
		
		foreach($entry in $GroupsMembership){
			$extract = ($entry -split ",")[0]
			$extract = ($extract -split "=")[1]
			$sumextract += $extract
		}
		
		$finalsumextract = ($sumextract | Sort-Object -Unique) -join ", "
		
		$GroupsTable = [PSCustomObject]@{
			"Groups" = $finalsumextract
		}
		
		$DomainGPOs = @(Collect-ADObjects -Domain $Domain -Server $Server -Collect GPOs -Property gpcfilesyspath,displayname -LDAP "displayname=$GPOName")
		
		$OUsMembership = @()
		$OUsMembershipList = $ExtractUser.distinguishedName
		$dnComponents = @($OUsMembershipList -split ',')
		$ouComponents = @(($dnComponents | Where-Object { $_ -like "OU=*" }) -replace "OU=","")
		$OUsTable = [PSCustomObject]@{
			"OUs" = $ouComponents -join ", "
		}
		
		foreach($ouComponent in $ouComponents){
			$ExtractBit = @(Collect-ADObjects -Domain $Domain -Server $Server -LDAP "ou=$ouComponent")
			$ExtractBit = $ExtractBit.gplink
			
			if ($ExtractBit) {
				# Split the gPLink string into individual GPO links
				$gpoLinks = $ExtractBit -split "\]"

				foreach ($gpoLink in $gpoLinks) {
					if ($gpoLink -ne "") {
						# Trim the leading "[" and apply the regex to extract the GUID
						if ($gpoLink.TrimStart("[") -match 'CN=\{([0-9A-Fa-f-]+)\},CN=Policies,CN=System,DC=') {
							$gpoGuid = $matches[1]

							# Collect GPO details using the GUID
							$GatherGPO = @(Collect-ADObjects -Domain $Domain -Server $Server -LDAP "cn={$gpoGuid}")

							# Assuming $GatheredGPOs is an array to hold all gathered GPOs
							$GatheredGPOs += $GatherGPO.displayname
						}
					}
				}
			}
		}
		
		$GPOsTable = [PSCustomObject]@{
			"GPOs" = $GatheredGPOs -join ", "
		}
		
		$InfoTable
		$MoreInfoTable
		$ChecksTable
		$GroupsTable
		$GPOsTable
		$OUsTable
	}
	
	elseif($ForeignPrincipals){
		$AllForeignSecurityPrincipals += @(Collect-ADObjects -Convert -Domain $Domain -LDAP "(&(objectCategory=foreignSecurityPrincipal)(CN=S-1-5-21*))")
		$FinalForeigns = foreach($ForeignSecurityPrincipal in ($AllForeignSecurityPrincipals | Sort-Object -Unique "Name" | Select-Object -ExpandProperty name)){
		
			[PSCustomObject]@{
				"Foreign Security Principal" = $ForeignSecurityPrincipal
			}
		}
		
		$FinalForeigns | Format-Table -AutoSize -Wrap
	}
	
	elseif($ConvertSID){
		$SIDuser = (New-Object System.Security.Principal.SecurityIdentifier($ConvertSID)).Translate([System.Security.Principal.NTAccount])
		
		[PSCustomObject]@{
			"Principal" = $SIDuser.Value
			"SID" = $ConvertSID
		}
	}
}

function Collect-ADObjects {

    <#

    .SYNOPSIS
    Collect-ADObjects | Author: Rob LP (@L3o4j)
    https://github.com/Leo4j/Collect-ADObjects

    .DESCRIPTION
    Collect Active Directory Objects

    #>

    param (
        [string]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,
        [string]$Server = $null,
        [int]$numOfThreads = 4,
		[Parameter(Mandatory = $false)]
        [ValidateSet("Users", "Computers", "Groups", "GPOs", "DomainControllers", "OUs", "Else", "Printers", "DomainPolicy", "OtherPolicies", "rIDManagers")]
        [string[]]$Collect = @("Users", "Computers", "Groups", "GPOs", "DomainControllers", "OUs", "Else", "Printers", "DomainPolicy", "OtherPolicies", "rIDManagers"),
		[string[]]$Property,
		[switch]$Enabled,
        [switch]$Disabled,
		[string]$Identity,
		[string]$LDAP,
		[switch]$Convert
    )
	
	$root = if ($Server) {
        "LDAP://$Server"
    } else {
        "LDAP://$Domain"
    }
	
	$rootDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($root)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($rootDirectoryEntry)
	
	# Construct the LDAP filter based on the -Collect parameter
    $filters = @()
	if ($Identity) {
        $filters += "(samAccountName=$Identity)"
    }
	elseif ($LDAP) {
        $filters += "($LDAP)"
    }
	else{
		foreach ($item in $Collect) {
			switch ($item) {
				"Users" { 
					$userFilter = "(objectCategory=person)"
					if ($Enabled) {
						$userFilter = "(&" + $userFilter + "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
					} elseif ($Disabled) {
						$userFilter = "(&" + $userFilter + "(userAccountControl:1.2.840.113556.1.4.803:=2))"
					}
					$filters += $userFilter
				}
				"Computers" { 
					$computerFilter = "(objectCategory=computer)"
					if ($Enabled) {
						$computerFilter = "(&" + $computerFilter + "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
					} elseif ($Disabled) {
						$computerFilter = "(&" + $computerFilter + "(userAccountControl:1.2.840.113556.1.4.803:=2))"
					}
					$filters += $computerFilter
				}
				"Groups" { $filters += "(objectCategory=group)" }
				"DomainControllers" { $filters += "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" }
				"OUs" { $filters += "(objectCategory=organizationalUnit)" }
				"GPOs" { $filters += "(objectClass=groupPolicyContainer)" }
				"Else" { $filters += "(&(!(objectCategory=person))(!(objectCategory=computer))(!(objectCategory=group))(!(objectCategory=organizationalUnit))(!(objectClass=groupPolicyContainer)))" }
				"Printers" { $filters += "(objectCategory=printQueue)" }
                "DomainPolicy" { $filters += "(objectClass=domainDNS)" }
                "OtherPolicies" { $filters += "(cn=Policies*)" }
				"rIDManagers" { $filters += "(objectClass=rIDManager)" }
			}
		}
	}
    # Combine the filters with an OR if multiple categories are specified
    $searcher.Filter = if ($filters.Count -gt 1) { "(|" + ($filters -join "") + ")" } else { $filters[0] }
	
    # Specify the properties to load if provided
    if ($Property) {
        $Property += "domain"  # Ensure 'domain' is always collected
        foreach ($prop in $Property) {
            $null = $searcher.PropertiesToLoad.Add($prop)
        }
    }
	
	$searcher.PageSize = 1000
	$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $results = $searcher.FindAll()

    [System.Collections.Generic.List[PSObject]]$records = New-Object 'System.Collections.Generic.List[PSObject]'
    foreach ($result in $results) {
        $properties = @{}
        foreach ($prop in $result.Properties.PropertyNames) {
            if ($result.Properties[$prop].Count -gt 1) {
                $properties[$prop] = $result.Properties[$prop]
            } else {
                $properties[$prop] = $result.Properties[$prop][0]
            }
        }
		
		# Convert properties if the -Convert switch is specified
        if ($Convert) {
            if ($properties.ContainsKey('objectsid')) {
                $properties['objectsid'] = GetSID-FromBytes -sidBytes $properties['objectsid']
            }
            $timestampProperties = @('pwdlastset', 'lastlogon', 'lastlogontimestamp', 'badpasswordtime', 'accountexpires')
            foreach ($timestampProperty in $timestampProperties) {
                if ($properties.ContainsKey($timestampProperty)) {
                    $properties[$timestampProperty] = Convert-LdapTimestamp -timestamp $properties[$timestampProperty]
                }
            }
            if ($properties.ContainsKey('userpassword')) {
                $properties['userpassword'] = $([System.Text.Encoding]::ASCII.GetString($($properties['userpassword'])))
            }
	    if ($properties.ContainsKey('unixUserPassword')) {
                $properties['unixUserPassword'] = $([System.Text.Encoding]::ASCII.GetString($($properties['unixUserPassword'])))
            }
	    if ($properties.ContainsKey('objectguid')) {
                $properties['objectguid'] = ([guid]::New(([string]::Join('', ($properties['objectguid'] | ForEach-Object { "{0:X2}" -f $_ }))[0..7] -join '') + "-" + 
                                              ([string]::Join('', ($properties['objectguid'] | ForEach-Object { "{0:X2}" -f $_ }))[8..11] -join '') + "-" +
                                              ([string]::Join('', ($properties['objectguid'] | ForEach-Object { "{0:X2}" -f $_ }))[12..15] -join '') + "-" +
                                              ([string]::Join('', ($properties['objectguid'] | ForEach-Object { "{0:X2}" -f $_ }))[16..19] -join '') + "-" +
                                              ([string]::Join('', ($properties['objectguid'] | ForEach-Object { "{0:X2}" -f $_ }))[20..31] -join ''))).Guid
            }
	    if ($properties.ContainsKey('samaccounttype')) {
                $properties['samaccounttype'] = switch ($($properties['samaccounttype'])) {
					805306368 { "User" }
					805306369 { "Computer" }
					805306370 { "Trust Account" }
					default { "Unknown" }
				}
            }
        }
		
		$properties['domain'] = $Domain
        $records.Add([PSCustomObject]$properties)
    }

    # Convert the records to Dictionary<string, object> for the C# code
    [System.Collections.Generic.List[System.Collections.Generic.Dictionary[string, object]]]$recordsArray = New-Object 'System.Collections.Generic.List[System.Collections.Generic.Dictionary[string, object]]'
    foreach ($record in $records) {
        $dict = New-Object 'System.Collections.Generic.Dictionary[String, Object]'
        foreach ($prop in $record.PSObject.Properties) {
            $dict.Add($prop.Name, $prop.Value)
        }
        $recordsArray.Add($dict)
    }

    $CollectedResults = [DataCollector.ProcessorClass]::ProcessRecords($recordsArray, $numOfThreads)
    
    return $CollectedResults
}

# Load the necessary assemblies
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
Add-Type -AssemblyName System.DirectoryServices

# Define the C# code for multithreaded processing
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Threading;
using System.Management.Automation;

namespace DataCollector
{
    public static class ProcessorClass
    {
        public static PSObject[] ProcessRecords(Dictionary<string, object>[] records, int numOfThreads)
        {
            Object[] results = ExecuteProcessing(records, numOfThreads);
            return Array.ConvertAll(results, item => (PSObject)item);
        }

        private static Object[] ExecuteProcessing(Dictionary<string, object>[] records, int numOfThreads)
        {
            int totalRecords = records.Length;
            IRecordHandler recordProcessor = new ActiveDirectoryRecordHandler();
            IResultsProcessor resultsHandler = new BasicResultsProcessor();
            int numberOfRecordsPerThread = totalRecords / numOfThreads;
            int remainders = totalRecords % numOfThreads;

            Thread[] threads = new Thread[numOfThreads];
            for (int i = 0; i < numOfThreads; i++)
            {
                int numberOfRecordsToProcess = numberOfRecordsPerThread;
                if (i == (numOfThreads - 1))
                {
                    numberOfRecordsToProcess += remainders;
                }

                Dictionary<string, object>[] sliceToProcess = new Dictionary<string, object>[numberOfRecordsToProcess];
                Array.Copy(records, i * numberOfRecordsPerThread, sliceToProcess, 0, numberOfRecordsToProcess);
                ProcessingThread processorThread = new ProcessingThread(i, recordProcessor, resultsHandler, sliceToProcess);
                threads[i] = new Thread(processorThread.ProcessThreadRecords);
                threads[i].Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }

            return resultsHandler.Complete();
        }

        class ProcessingThread
        {
            readonly int id;
            readonly IRecordHandler recordProcessor;
            readonly IResultsProcessor resultsHandler;
            readonly Dictionary<string, object>[] objectsToBeProcessed;

            public ProcessingThread(int id, IRecordHandler recordProcessor, IResultsProcessor resultsHandler, Dictionary<string, object>[] objectsToBeProcessed)
            {
                this.id = id;
                this.recordProcessor = recordProcessor;
                this.resultsHandler = resultsHandler;
                this.objectsToBeProcessed = objectsToBeProcessed;
            }

            public void ProcessThreadRecords()
            {
                for (int i = 0; i < objectsToBeProcessed.Length; i++)
                {
                    Object[] result = recordProcessor.ProcessRecord(objectsToBeProcessed[i]);
                    resultsHandler.ProcessResults(result);
                }
            }
        }

        interface IRecordHandler
        {
            PSObject[] ProcessRecord(Dictionary<string, object> record);
        }

        class ActiveDirectoryRecordHandler : IRecordHandler
        {
            public PSObject[] ProcessRecord(Dictionary<string, object> record)
            {
                try
                {
                    PSObject adObj = new PSObject();
                    foreach (var prop in record)
                    {
                        adObj.Members.Add(new PSNoteProperty(prop.Key, prop.Value));
                    }
                    return new PSObject[] { adObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        interface IResultsProcessor
        {
            void ProcessResults(Object[] t);
            Object[] Complete();
        }

        class BasicResultsProcessor : IResultsProcessor
        {
            private readonly Object lockObj = new Object();
            private readonly List<Object> processed = new List<Object>();

            public void ProcessResults(Object[] results)
            {
                lock (lockObj)
                {
                    if (results.Length != 0)
                    {
                        for (var i = 0; i < results.Length; i++)
                        {
                            processed.Add(results[i]);
                        }
                    }
                }
            }

            public Object[] Complete()
            {
                return processed.ToArray();
            }
        }
    }
}
"@

function Convert-LdapTimestamp {
    param([string]$timestamp)
    if ($timestamp -eq "0" -OR $timestamp -eq "9223372036854775807") {
        return "NEVER"
    }
    else {
        [datetime]$epoch = "1/1/1601"
        $date = $epoch.AddTicks($timestamp)
        return $date
    }
}

function GetSID-FromBytes {
	param (
        [byte[]]$sidBytes
    )
	
	$sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
	$stringSid = $sid.Value
	return $stringSid
}
