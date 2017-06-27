#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52456);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_cve_id("CVE-2011-0037");
  script_bugtraq_id(46540);
  script_osvdb_id(71017);

  script_name(english:"MS KB2491888: Microsoft Malware Protection Engine (MMPE) Privilege Escalation");
  script_summary(english:"Checks Microsoft Malware Protection Engine version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerable version of Microsoft Malware Protection Engine (MMPE) is
installed on the remote system. MMPE is typically included with
Microsoft anti-malware products such as Windows Live OneCare,
Microsoft Security Essentials, Microsoft Forefront Client Security,
Microsoft Forefront Client Security, Microsoft Forefront Endpoint
Protection 2010, and Microsoft Malicious Software Removal Tool.

A local user may be able to gain local system privileges by creating a
specially crafted registry key before a system is scanned using
Microsoft Malware Protection Engine.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2491888");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2510781");
  script_set_attribute(attribute:"solution", value:
"Update the malware definitions for the installed Microsoft anti-
malware product.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:malware_protection_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "fcs_installed.nasl", "liveonecare_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port))  exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Figure out where it is installed.
path = NULL;
info = '';
info2 = '';
engine_version = NULL;

fixed_engine_version = "1.1.6603.0";

engine_version = get_kb_item("Antivirus/Forefront_Client_Security/engine_version");
if (!isnull(engine_version))
{
  if (ver_compare(ver:engine_version, fix:fixed_engine_version) == -1)
  {
    info +=
      '\n  Product           : Microsoft Forefront Client Security'+
      '\n  Installed version : ' + engine_version +
      '\n  Fixed version     : ' + fixed_engine_version + '\n';
  }
  else info2 += 'Microsoft Forefront Client Security with MMPE version '+ engine_version + ". ";
}

# Live One care
engine_version = get_kb_item("Antivirus/OneCare/onecare_engine_version");
if (!isnull(engine_version))
{
  if (ver_compare(ver:engine_version, fix:fixed_engine_version) == -1)
  {
    info +=
     '\n  Product           : Windows Live OneCare'+
     '\n  Installed version : ' + engine_version +
     '\n  Fixed version     : ' + fixed_engine_version + '\n';
  }
  else info2 += 'Windows Live OneCare with MMPE version '+ engine_version + ". ";
}

# Microsoft Windows Defender
engine_version = NULL;

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
  # Check the version of the main exe.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.+Windows Defender\\Definition Updates).+", replace:"\1\Default\MpEngine.dll", string:path);
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    found =1 ;
    CloseFile(handle:fh);
  }

  if (found && !isnull(engine_version))
  {
    if (ver_compare(ver:engine_version, fix:fixed_engine_version) == -1)
    {
      info +=
       '\n  Product           : Microsoft Windows Defender'+
       '\n  Installed version : ' + engine_version +
       '\n  Fixed version     : ' + fixed_engine_version + '\n';
    }
    else info2 += 'Microsoft Windows Defender with MMPE version ' + engine_version + ". ";
  }
}

# Microsoft Security Essentials
engine_version = NULL;

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry again.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
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
  # Check the version of the main exe.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\MsMpEng.exe", string:path);
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
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
    found = 1;
    CloseFile(handle:fh);
  }

  if (found && !isnull(engine_version))
  {
    if (ver_compare(ver:engine_version, fix:fixed_engine_version) == -1)
    {
      info +=
       '\n  Product           : Microsoft Security Essentials / Forefront Endpoint Protection'+
       '\n  Installed version : ' + engine_version +
       '\n  Fixed version     : ' + fixed_engine_version + '\n';
    }
    else info2 += 'Microsoft Security Essentials / Forefront Endpoint Protection with MMPE version ' + engine_version + ". ";
  }
}
RegCloseKey(handle:hklm);
NetUseDel();

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
else exit(0, "Nessus could not find evidence of affected Microsoft anti-malware products installed.");
