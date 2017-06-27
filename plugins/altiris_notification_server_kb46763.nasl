#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(44339);
  script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2009-3035");
  script_bugtraq_id(37953);
  script_osvdb_id(62010);
  script_xref(name:"Secunia", value:"38356");

  script_name(english:"Altiris Notification Server Static Encryption Key (KB46763)");
  script_summary(english:"Checks version of Altiris.Web.NS.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is prone to an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running Symantec Altiris Notification
Server 6.0 earlier than SP3 R12. Such versions are potentially
affected by a local information disclosure vulnerability because the
application uses a static encryption key for encrypted credentials
entered by an administrator.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?887bac22");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?942c6f9b" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Altiris Notification Server 6.0 SP3 R12 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("global_settings.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Can't open socket to port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Altiris";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, "Altiris is not installed.");
}


# Check the version of Altiris.Web.NS.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Notification Server\bin\Altiris.Web.NS.dll", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

if (isnull(ver)) exit(1, "Could not detect the Altiris.Web.NS.dll file version.");

version = ver[0]+'.'+ver[1]+'.'+ver[2]+'.'+ver[3];

# Check the version number.
if (!isnull(ver) && ver[0] == 6)
{
  fix = split("6.0.6075.120", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' +
          "A vulnerable version of 'Altiris.Web.NS.dll' was found :" + '\n'+
          '\n' +
          'Path              : ' + path+'\\Notification Server\\bin' + '\n' +
          'Installed version : ' + version + '\n' +
          'Fixed version     : 6.0.6075.120' + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port:port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;
}
exit(0, 'The remote host is not affected because Altiris.Web.NS.dll version '+version+' was found.');
