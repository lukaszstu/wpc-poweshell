$trusted_users=@("DOMAIN\USER","BUILTIN\Administrators","NT AUTHORITY\SYSTEM","NT SERVICE\TrustedInstaller")
$dangerous_file_rights=@("FullControl","Write","Modify","ChangePermissions","WriteAttributes","WriteExtendedAttributes","AppendData","Delete")
$dangerous_registry_rights=@("FullControl")

function Test-FileRights([string] $path)
{
	Begin
	{
	}
	Process
	{
		$violating=@()
		try{
			(Get-Acl $path).Access | ForEach-Object{
				$danger=$FALSE
				$_.FileSystemRights.ToString().Replace(" ","").Split(",") | ForEach-Object{
					if ($dangerous_file_rights -contains $_){
						$danger=$TRUE
					}
				}
				if  ($danger -and !($trusted_users -contains $_.IdentityReference) -and ($_.AccessControlType -eq "Allow")){
					$violating+=$_
				}
			}
		}catch [System.UnauthorizedAccessException]{
			write-debug -Message ("Could not access file: "+$path)
		}
		return $violating
	}
	End
	{
	}
}

<#
.SYNOPSIS
   Get Unprotected Service binaries
.DESCRIPTION
   Enumerates binaries referenced by services that can be modified by untrusted users
#>
function Get-UnprotectedServiceBinaries
{
	Begin
	{
	}
	Process
	{
		$services = get-wmiobject -query 'select * from Win32_Service';
		$paths=@()
		$services | ForEach-Object {
			$path=$_.PathName
			if ($path.StartsWith('"')){
				$parts=$path.Split('"')
				$p=$parts[1]
				if (!($paths -contains $p)){
					$paths+=$p
				}
			}else{
				$p=$path.Split(" ")[0]
				if (!($paths -contains $p)){
					$paths+=$p
				}
			}
		}

		$paths | ForEach-Object{
			$current_path=$_
			$rights=Test-FileRights($current_path)
			if ($rights){
				$rights | ForEach-Object{
					$out_props=@{Path=$current_path;Identityreference=$_.IdentityReference;FileSystemRights=$_.FileSystemRights}	
					Write-Host ((new-object psobject -Property $out_props)|Format-Table|Out-String)
				}
			}
				
		}
	}
	End
	{
	}
}

<#
.SYNOPSIS
   Get Unprotected files from arbitrary path
.DESCRIPTION
   Enumerates binaries referenced by services that can be modified by untrusted users
#>
function Get-UnprotectedFiles([string] $path)
{
	Begin
	{
	}
	Process
	{
		Get-ChildItem $path | ForEach-Object{
			$current_path=$path+$_
			$rights=Test-FileRights($current_path)
			if ($rights){
				$rights | ForEach-Object{	
					$out_props=@{Path=$current_path;Identityreference=$_.IdentityReference;FileSystemRights=$_.FileSystemRights}	
					Write-Host ((new-object psobject -Property $out_props)|Format-Table|Out-String)
				}
			}
		}
	}
	End
	{
	}
}

<#
.SYNOPSIS
   Get Unprotected files from arbitrary path
.DESCRIPTION
   Enumerates binaries referenced by services that can be modified by untrusted users
#>
function Get-UnprotectedSystemFiles()
{
	Begin
	{
	}
	Process
	{
		$path=((Get-Item env:\SYSTEMROOT).Value)+"\system32\"
		Get-UnprotectedFiles($path)
	}
	End
	{
	}
}

<#
.SYNOPSIS
   Get Unprotected files from arbitrary path
.DESCRIPTION
   Enumerates binaries referenced by services that can be modified by untrusted users
#>
function Get-UnprotectedPathFiles()
{
	Begin
	{
	}
	Process
	{
		$path=(Get-Item env:\PATH).Value
		$path.Split(";") | ForEach-Object{
			$path_part=([Environment]::ExpandEnvironmentVariables($_))
			if (!($path_part.EndsWith("\"))){
				$path_part+="\"
			}
			Get-UnprotectedFiles($path_part)
		}
	}
	End
	{
	}
}

<#
.SYNOPSIS
   User owned Service keys
.DESCRIPTION
   Checks for Service descriptors in Registry which can be modified by untrusted users
#>
function Get-UserOwnedServiceKeys
{
	Begin
	{
	}
	Process
	{
		$services=Get-ChildItem -path hklm:\system\currentcontrolset\services\
		$services | ForEach-Object{
			$service=$_
			$service_access=$_.GetAccessControl().Access
			$service_access | ForEach-Object{
				$danger=$FALSE
				$_.RegistryRights.ToString().Replace(" ","").Split(",") | ForEach-Object{
					if ($dangerous_registry_rights -contains $_){
						$danger=$TRUE
					}
				}
				if  ($danger -and !($trusted_users -contains $_.IdentityReference) -and ($_.AccessControlType -eq "Allow")){
					$out_props=@{ServiceName=$service.Name;IdentityReference=$_.IdentityReference;RegistryRights=$_.RegistryRights;AccessControlType=$_.AccessControlType}
					Write-Host ((new-object psobject -Property $out_props)|Format-Table|Out-String)
				}
			}	
		}
	}
	End
	{
	}
}
