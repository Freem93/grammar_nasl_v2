#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100051);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/19 13:50:49 $");

  script_cve_id("CVE-2017-0290");
  script_bugtraq_id(98330);
  script_osvdb_id(157157);
  script_xref(name:"MSKB", value:"4022344");
  script_xref(name:"IAVA", value:"2017-A-0140");

  script_name(english:"MS Security Advisory 4022344: Security Update for Microsoft Malware Protection Engine");
  script_summary(english:"Checks engine version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an antimalware application installed that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Malware Protection Engine (MMPE) installed on
the remote Windows host is prior to 1.1.13704.0. It is, therefore,
affected by a remote code execution vulnerability in the NScript
component in mpengine.dll due to a type confusion error. An
unauthenticated, remote attacker can exploit this, via a specially
crafted file, to execute arbitrary code in the security context of the
LocalSystem account.

Nessus has checked if a vulnerable version of MMPE is being used by
any of the following applications :

  - Microsoft Forefront Endpoint Protection 2010
  - Microsoft Endpoint Protection
  - Microsoft Forefront Security for SharePoint
  - Microsoft System Center Endpoint Protection
  - Microsoft Security Essentials
  - Windows Defender for Windows 7, Windows 8.1, Windows RT
    8.1, Windows 10, Windows 10 1511, Windows 10 1607,
    Windows 10 1703, and Windows Server 2016
  - Windows Intune Endpoint Protection ");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/4022344.aspx");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the scan engine for the relevant
antimalware applications. Refer to KB4022344 for information on how to
verify MMPE has been updated.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:malware_protection_engine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "fcs_installed.nasl");
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

fixed_engine_version = "1.1.13704.0";
last_vulnerable = "1.1.13701.0";

# Forefront Client Security (either both or neither of these will be in the KB)
engine_version = get_kb_item("Antivirus/Forefront_Client_Security/engine_version");
fcs_path = get_kb_item("Antivirus/Forefront_Client_Security/path");
if (!isnull(engine_version))
{
  antimalware_installed = TRUE;

  if (ver_compare(ver:engine_version, fix:last_vulnerable) <= 0)
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
    if (ver_compare(ver:engine_version, fix:last_vulnerable) <= 0)
    {
      info +=
       '\n  Product           : Microsoft Security Essentials / Forefront Endpoint Protection / System Center Endpoint Protection'+
       '\n  Path              : ' + share[0] + ':' + exe +
       '\n  Installed version : ' + engine_version +
       '\n  Fixed version     : ' + fixed_engine_version + '\n';
    }
    else info2 += 'Microsoft Security Essentials / Forefront Endpoint Protection / System Center Endpoint Protection with MMPE version ' + engine_version + ". ";
  }
}

# Microsoft Windows Defender
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
      # this is the path smb_kb4022344.nasl checks
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
        if (ver_compare(ver:engine_version, fix:last_vulnerable) <= 0)
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

if (info)
{
  report = '\n' +
    "Nessus found following vulnerable product(s) installed :" +'\n'+
    info;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);

  exit(0);
}
else if(info2) exit(0,"The following instance(s) of MMPE are installed and not vulnerable : "+ info2);
else exit(0, "Nessus could not find evidence of affected Microsoft antimalware products installed.");
