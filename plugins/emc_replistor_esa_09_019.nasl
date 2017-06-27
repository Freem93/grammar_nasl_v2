#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45371);
  script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");

  script_cve_id("CVE-2009-3744");
  script_bugtraq_id(36738);
  script_osvdb_id(59147);
  script_xref(name:"Secunia", value:"37092");

  script_name(english:"EMC RepliStor rep_srv.exe Crafted TCP Packet Remote DoS (ESA-09-019)");
  script_summary(english:"Checks file version of rep_srv.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote data recovery service is susceptible to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"According to its version, the EMC RepliStor Server service running on
the remote host reportedly may crash while attempting to process a
specially crafted network packet.

An unauthenticated, remote attacker can leverage this issue to deny
service to legitimate users.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_emc_repli_crash.html");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2009/Oct/148"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to RepliStor 6.4 P2 / RepliStor 6.3 SP3 / RepliStor 6.2 SP5 P2
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the affected service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    services &&
    "RepliStorServer" >!< services
  ) exit(0, "The RepliStor Server service is not running, and the software may not even be installed.");
}


# Detect where RepliStor is installed.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
key = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && prod =~ "^RepliStor$")
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);
      break;
    }
  }
}


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}


# Find where it's installed.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
# - Look in alternate locations if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\loglook.exe";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(value))
    {
      path = value[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }
    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  key = "SYSTEM\CurrentControlSet\Services\RepliStorServer";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"ImagePath");
    if (!isnull(value))
    {
      path = value[1];
      path = ereg_replace(pattern:'^"(.+)\\\\rep_srv\\.exe".*', replace:"\1", string:path);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "EMC RepliStor is not installed.");
}
NetUseDel(close:FALSE);


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\rep_srv.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file               : exe,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  version = join(ver, sep:".");

  if (ver[0] == 6 && ver[1] == 4) fixed_version = '6.4.0.30';
  else if (ver[0] == 6 && ver[1] == 3) fixed_version = '6.3.3.5';
  else fixed_version = '6.2.5.3';

  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report =
          '\n  File              : ' + path + '\\rep_srv.exe' +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fixed_version + '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;

  exit(0, "The file version of '"+(share-'$')+":"+exe+"' is "+version+" and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");
