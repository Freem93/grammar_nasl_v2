#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33225);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2008-2794");
  script_bugtraq_id(29708);
  script_osvdb_id(46305);
  script_xref(name:"Secunia", value:"30741");

  script_name(english:"Altiris Notification Server Agent GUI Local Privilege Escalation (KB 39159)");
  script_summary(english:"Checks version of AeXNSAgent.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a local
privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"Altiris Notification Server Agent, also known as Altiris Agent, is
installed on the remote host, allowing it to be managed by an Altiris
Notification Server.

The installed version of the Altiris Agent is reportedly vulnerable to
a Shatter Attack involving its GUI that can allow local users to
escalate their privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.insomniasec.com/advisories/ISVA-080623.1.htm");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2fb19d9" );
 script_set_attribute(attribute:"solution", value:
"Retrieve the patch Altiris_NS_6_0_SP3_KB39159.exe and use that to
upgrade all agent machines from the Notification Server.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/20");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Altiris\Altiris Agent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
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
  exit(0);
}


# Determine the version of AeXNSAgent.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\AeXNSAgent.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
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


# Check the version number.
if (!isnull(ver))
{
  fix = split("6.0.0.2394", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "  File              : AeXNSAgent.exe\n",
          "  Path              : ", path, "\n",
          "  Installed version : ", ver[0], ".", ver[1], ".", ver[2], ".", ver[3], "\n",
          "  Fix               : 6.0.0.2394\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
