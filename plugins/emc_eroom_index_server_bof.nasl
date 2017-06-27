#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55732);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2011-1741");
  script_bugtraq_id(48712);
  script_osvdb_id(73884);

  script_name(english:"EMC Documentum eRoom Indexing Server Hummingbird Client Connector Buffer Overflow");
  script_summary(english:"Checks to see if the vulnerable service is present");

  script_set_attribute(attribute:"synopsis", value:
"A text indexing service on the remote host has a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Hummingbird Client Connector, bundled with EMC Documentum eRoom's
Indexing Server, has a buffer overflow vulnerability. Making an
unspecified request can result in a stack-based buffer overflow. A
remote, unauthenticated attacker could exploit this to execute
arbitrary code.

Documentum eRoom versions 7.x are affected.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-236/");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/518897/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/518897/30/0/threaded"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to EMC Documentum eRoom 7.4.3.f or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_eroom");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# First check if the indexing server is installed
installed = FALSE;
list = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (isnull(list)) exit(1, 'The "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName" KB items are missing.');

foreach key (keys(list))
{
  prod = list[key];
  if (isnull(prod)) continue;

  if (prod == 'eRoom Indexing Server')
  {
    installed = TRUE;
    break;
  }
}

if (!installed)
  exit(0, 'Unable to find evidence of eRoom Indexing Server in the registry.');

# Then check if the Hummingbird search service is installed
status = get_kb_item_or_exit('SMB/svc/Hummingbird Connector');

# If the service exists, make sure it's currently running (unless paranoid)
if (report_paranoia < 2 && status != SERVICE_ACTIVE)
  exit(0, "The Hummingbird search service is installed but not active.");


# Lastly, make sure eRoom is version 7.x
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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
  exit(1, "Can't connect to the remote registry.");
}

key = "SOFTWARE\eRoom\eRoom Server\7.0\Full Text";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;

if (!isnull(key_h))
{
  ret = RegQueryValue(handle:key_h, item:'InstallDir');
  if (!isnull(ret))
    path = ret[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'Failed to get eRoom 7.x installation directory from the registry.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\bin\\ftserver.exe', string:path);

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
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
  CloseFile(handle:fh);
  exe_found = TRUE;
}
else
  exe_found = FALSE;

NetUseDel();

if (!exe_found)
  exit(1, 'Error verifying the location of the eRoom installation.');

if (report_verbosity > 0)
{
  report =
    '\nNessus discovered the vulnerable "Hummingbird Connector" service is installed' +
    '\nalong with the following eRoom Indexing Server 7.x installation :\n\n' +
    path + '\n';

  if (report_paranoia >= 2)
  {
    report +=
       '\nNote though that Nessus did not check whether this service is running' +
       '\nbecause of the Report Paranoia setting in effect when this scan was run.\n';
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);
