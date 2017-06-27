#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76123);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_cve_id("CVE-2014-2779");
  script_bugtraq_id(68076);
  script_osvdb_id(108198);
  script_xref(name:"IAVA", value:"2014-A-0090");

  script_name(english:"MS Security Advisory 2974294: Vulnerability in Microsoft Malware Protection Engine Could Allow Denial of Service");
  script_summary(english:"Checks engine version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an antimalware application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerable version of Microsoft Malware Protection Engine (MMPE) is
installed on the remote host. Scanning a maliciously crafted file
could prevent the Malware Protection Engine from monitoring affected
systems until the file is manually removed and the service is
restarted. This plugin checks if a vulnerable version of MMPE is being
used by any of the following applications :

  - Microsoft Forefront Client Security
    - Microsoft Forefront Endpoint Protection 2010
    - Microsoft System Center 2012 Endpoint Protection
    - Microsoft Malicious Software Removal Tool
    - Microsoft Security Essentials
    - Microsoft Security Essentials Prerelease
    - Windows Defender for Windows 8, Windows 8.1, Windows
    Server 2012 and Windows Server 2012 R2
    - Windows Defender for Windows XP, Windows Server 2003,
    Windows Vista, Windows Server 2008, Windows 7, and
    Windows Server 2008 R2

These applications are only affected if they are using a scan engine
prior to 1.1.10701.0.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2974294");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the scan engine for the relevant
antimalware applications. Refer to KB2510781 for information on how to
verify MMPE has been updated.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:malware_protection_engine");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "fcs_installed.nasl", "smb_mrt_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# indicates if any antimalware products were found. this is used
# to determine whether or not the plugin should check if defender is affected
antimalware_installed = FALSE;

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Figure out where it is installed.
path = NULL;
info = '';
info2 = '';
engine_version = NULL;

fixed_engine_version = "1.1.10701.0";

# Forefront Client Security (either both or neither of these will be in the KB)
engine_version = get_kb_item("Antivirus/Forefront_Client_Security/engine_version");
fcs_path = get_kb_item("Antivirus/Forefront_Client_Security/path");
if (!isnull(engine_version))
{
  antimalware_installed = TRUE;

  if (ver_compare(ver:engine_version, fix:fixed_engine_version) == -1)
  {
    info +=
      '\n  Product           : Microsoft Forefront Client Security'+
      '\n  Path              : ' + fcs_path +
      '\n  Installed version : ' + engine_version +
      '\n  Fixed version     : ' + fixed_engine_version + '\n';
  }
  else info2 += 'Microsoft Forefront Client Security with MMPE version '+ engine_version + ". ";
}

# Microsoft Security Essentials
# Microsoft Security Essentials Prerelease
# Forefront Endpoint Protection
# System Center Endpoint Protection
engine_version = NULL;

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry again.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"EngineVersion");
  if (!isnull(value)) engine_version = value[1];

  RegCloseKey(handle:key_h);
}

path = NULL;
key = "SOFTWARE\Microsoft\Microsoft Antimalware";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

if(!isnull(path))
{
  found = 0;
  # Check if the main exe exists.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\MsMpEng.exe", string:path);
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }
  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    antimalware_installed = TRUE;
    found = 1;
    CloseFile(handle:fh);
  }

  if (found && !isnull(engine_version))
  {
    if (ver_compare(ver:engine_version, fix:fixed_engine_version) == -1)
    {
      info +=
       '\n  Product           : Microsoft Security Essentials / Microsoft Security Essentials Prerelease / Forefront Endpoint Protection / System Center Endpoint Protection'+
       '\n  Path              : ' + share[0] + ':' + exe +
       '\n  Installed version : ' + engine_version +
       '\n  Fixed version     : ' + fixed_engine_version + '\n';
    }
    else info2 += 'Microsoft Security Essentials / Microsoft Security Essentials Prerelease / Forefront Endpoint Protection / System Center Endpoint Protection with MMPE version ' + engine_version + ". ";
  }
}

# Microsoft Windows Defender
# Microsoft Windows Defender for Windows 8
# defender is apparently disabled when other antimalware products are installed,
# so it will only be checked if the plugin hasn't detected other products are present
if (!antimalware_installed)
{
  defender_enabled = TRUE;
  engine_version = NULL;

  # Check if Windows Defender is disabled via group policy
  key = "SOFTWARE\Policies\Microsoft\Windows Defender";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"DisableAntiSpyware");
    if (!isnull(value))
    {
      if (value[1] > 0)
      {
        defender_enabled = FALSE;
      }
    }
    RegCloseKey(handle:key_h);
  }
  key = "SOFTWARE\Microsoft\Windows Defender";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"DisableAntiSpyware");
    if (!isnull(value))
    {
      if (value[1] > 0)
      {
        defender_enabled = FALSE;
      }
    }
    RegCloseKey(handle:key_h);
  }
  if (defender_enabled)
  {
    key = "SOFTWARE\Microsoft\Windows Defender\Signature Updates";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"EngineVersion");
      if (!isnull(value)) engine_version = value[1];

      RegCloseKey(handle:key_h);
    }

    path = NULL;
    key = "SOFTWARE\Microsoft\Windows Defender\Signature Updates";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"SignatureLocation");
      if (!isnull(value)) path = value[1];

      RegCloseKey(handle:key_h);
    }

    if(!isnull(path))
    {
      found = 0;
      defender_dll = NULL;
      # Check the version of the main exe.
      share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
      # this is the path smb_kb2491888.nasl checks
      dll1 =  ereg_replace(pattern:"^[A-Za-z]:(.+Windows Defender\\Definition Updates).+", replace:"\1\Default\MpEngine.dll", string:path);
      # this path works for Windows Defender on Windows 8
      dll2 =  ereg_replace(pattern:"^[A-Za-z]:(.+)$", replace:"\1\MpEngine.dll", string:path);
      NetUseDel(close:FALSE);
      rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
      if (rc != 1)
      {
        NetUseDel();
        audit(AUDIT_SHARE_FAIL, share);
      }
      fh = CreateFile(
        file:dll1,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        found =1 ;
        defender_dll = share[0] + ':' + dll1;
        CloseFile(handle:fh);
      }

      if (found == 0)
      {
        fh = CreateFile(
          file:dll2,
          desired_access:GENERIC_READ,
          file_attributes:FILE_ATTRIBUTE_NORMAL,
          share_mode:FILE_SHARE_READ,
          create_disposition:OPEN_EXISTING
        );
        if (!isnull(fh))
        {
          found =1 ;
          defender_dll = share[0] + ':' + dll2;
          CloseFile(handle:fh);
        }
      }

      if (found && !isnull(engine_version))
      {
        if (ver_compare(ver:engine_version, fix:fixed_engine_version) == -1)
        {
          info +=
           '\n  Product           : Microsoft Windows Defender'+
           '\n  Path              : ' + defender_dll +
           '\n  Installed version : ' + engine_version +
           '\n  Fixed version     : ' + fixed_engine_version + '\n';
        }
        else info2 += 'Microsoft Windows Defender with MMPE version ' + engine_version + ". ";
      }
    }
  }
}

RegCloseKey(handle:hklm);
NetUseDel();

# Microsoft Malicious Software Removal Tool
# Only May 2014 or earlier versions of the Microsoft Malicious Software Removal Tool are vuln
# ie we are patched in June 2014 (5.13.10300.0)
mrt_version = get_kb_item('SMB/MRT/Version');
if (!isnull(mrt_version))
{
  if (ver_compare(ver:mrt_version, fix:'5.13.10300.0') < 0)
  {
    info +=
      '\n  Product           : Microsoft Malicious Software Removal Tool' +
      '\n  Installed version : ' + mrt_version +
      '\n  Fixed version     : 5.13.10300.0 (June 2014)\n';
  }
  else info2 += 'Microsoft Malicious Software Removal Tool ' + mrt_version + '. ';
}

if (info)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      "Nessus found following vulnerable product(s) installed :" +'\n'+
      info;
      security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else if(info2) exit(0,"The following instance(s) of MMPE are installed and not vulnerable : "+ info2);
else exit(0, "Nessus could not find evidence of affected Microsoft antimalware products installed.");
