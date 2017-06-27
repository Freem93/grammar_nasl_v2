#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34242);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2008-2326", "CVE-2008-3630");
  script_bugtraq_id(31093, 31091);
  script_osvdb_id(48019, 48020);

  script_name(english:"Bonjour < 1.0.5 Multiple Vulnerabilities (APPLE-SA-2009-09-09)");
  script_summary(english:"Checks mDNSResponder.exe version");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"Bonjour for Windows is installed on the remote host. The installed
version is older than 1.0.5 and thus affected by multiple issues :

  - A NULL pointer dereference issue could crash a remote
    Bonjour service while resolving a maliciously crafted
    '.local' domain name containing a long DNS label.

  - Due to a weakness in DNS protocol implementation, it may
    be possible to spoof DNS responses for unicast DNS
    queries sent from an application that uses Bonjour APIs
    to send unicast DNS queries. It should be noted that
    there are currently no known applications that use
    Bonjour
    APIs for unicast DNS hostname resolution.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/15334");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd5604f");
 script_set_attribute(attribute:"solution", value:"Upgrade to Bonjour for Windows version 1.0.5.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/18");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


if (report_paranoia < 2)
{
  svcs = get_kb_item("SMB/svcs");
  if (svcs && "Bonjour Service" >!< svcs) exit(0);
}

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# First try this...
path = NULL;

key = "SOFTWARE\Apple Inc.\Bonjour";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If Bonjour is installed...
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
    path = item[1];

  RegCloseKey(handle:key_h);
}

# If not, try the installer entries...
if(isnull(path))
{
  # Figure out where the installer recorded information about it.
  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (isnull(list)) exit(0);

  installstring = NULL;
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "Bonjour" >< prod)
    {
     installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
     installstring = str_replace(find:"/", replace:"\", string:installstring);
     break;
    }
  }

  key = installstring;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
   {
    # If Bonjour is installed...
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    path = item[1];

    RegCloseKey(handle:key_h);
  }
}

# Finally, try the services registry entry...
if(isnull(path))
{
  key = "SYSTEM\CurrentControlSet\Services\Bonjour Service";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
   {
    # If Bonjour is installed...
    item = RegQueryValue(handle:key_h, item:"ImagePath");
    if (!isnull(item))
    {
      path = item[1];
      path = str_replace(string:path,find:'"',replace:"");
      path = str_replace(string:path,find:'mDNSResponder.exe',replace:"");
    }
    RegCloseKey(handle:key_h);
   }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\mDNSResponder.exe", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


if(!isnull(ver))
{
  fix = split("1.0.5.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1], ".", ver[2]);
        report = string(
          "\n",
          "Version ", version, " of Bonjour for Windows is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
