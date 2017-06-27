#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31417);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2008-1473", "CVE-2008-1754");
  script_bugtraq_id(28110, 28707);
  script_osvdb_id(42714, 44388);
  script_xref(name:"Secunia", value:"29319");
  script_xref(name:"Secunia", value:"29771");

  script_name(english:"Altiris AClient < 6.9.164 Multiple Local Vulnerabilities");
  script_summary(english:"Checks version of aclient.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
privilege escalation vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of the Altiris Client Agent (aclient) installed on the
remote host reportedly is susceptible to a shatter attack that could
allow a local user to elevate his or her privileges on the affected
system.

In addition, the Altiris Deployment Solution reportedly stores the
AClient password in system memory. By dumping system memory for
AClient.exe, a local user could potentially recover the password and
use that to gain access to the local agent admin interface, which in
turn could allow for code execution with system level privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.insomniasec.com/advisories/ISVA-081020.1.htm");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497617/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.03.10.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.04.10.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Altiris Deployment Solution Agent 6.9.164 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264, 310);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/12");

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

key = "SOFTWARE\Altiris\Client Service";
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


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\aclient.exe", string:path);
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
  fix = split("6.9.164", sep:'.', keep:FALSE);
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
          "Version ", version, " of the Altiris Client Agent is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
