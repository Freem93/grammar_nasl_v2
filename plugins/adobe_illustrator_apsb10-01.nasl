#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43861);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2009-3952", "CVE-2009-4195");
  script_bugtraq_id(37192, 37666);
  script_osvdb_id(60632, 61622);
  script_xref(name:"Secunia", value:"37563");

  script_name(english:"Adobe Illustrator Multiple Vulnerabilities (APSB10-01)");
  script_summary(english:"Checks version of MPS.dll");

  script_set_attribute(attribute:"synopsis", value:
"The graphics editor on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator CS4 installed on the remote windows
host is using a library that is potentially affected by multiple
vulnerabilities. An attacker could exploit these flaws to execute
arbitrary code on the remote host subject to the privileges of the
user id running the application.");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-01.html");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Illustrator CS4 v14.0.0');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");
  script_require_ports(139,445);
  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

path = get_kb_item('SMB/Adobe Illustrator/path');
if (isnull(path)) exit(1, "The 'SMB/Adobe Illustrator/path' KB item is missing.");
prod = get_kb_item('SMB/Adobe Illustrator/product');
if (isnull(prod)) exit(1, "The 'SMB/Adobe Illustrator/product' KB item is missing.");

name   = kb_smb_name();
port   = kb_smb_transport();
#if (!get_port_state(port)) exit(1, 'Port '+port+' is not open.');
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Can't open socket to port "+port+".");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\MPS.dll", string:path);

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Cannot connect to " + share + "share.");
}

fh = CreateFile(
       file:dll,
       desired_access:GENERIC_READ,
       file_attributes:FILE_ATTRIBUTE_NORMAL,
       share_mode:FILE_SHARE_READ,
       create_disposition:OPEN_EXISTING);

if (isnull(fh)) exit(1, "Couldn't open file handle for MPS.dll");

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();
if (isnull(ver)) exit(1, "Couldn't determine version of MPS.dll");

if (
  (
    prod == "Adobe Illustrator CS4" &&
    (
      ver[0] < 4 ||
      (ver[0] == 4 && ver[1] < 9) ||
      (ver[0] == 4 && ver[1] == 9 && ver[2] < 16) ||
      (ver[0] == 4 && ver[1] == 9 && ver[2] == 16 && ver[3] < 4555)
    )
  ) ||
  (
    prod == "Adobe Illustrator CS3" &&
    (
      ver[0] < 4 ||
      (ver[0] == 4 && ver[1] < 9) ||
      (ver[0] == 4 && ver[1] == 9 && ver[2] < 16)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '  DLL     : MPS.dll' + '\n' +
      '  Path    : ' + path + '\n' +
      '  Version : ' + ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3] + '\n';
    if (prod == "Adobe Illustrator CS3") report = report + '  Fix     : ' + '4.9.16.0' + '\n\n';
    else report = report + '  Fix     : ' + '4.9.16.4555' + '\n\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port:port, extra:report);
  exit(0);
}
else exit(0, 'The remote host is not affected because MPS.dll version '+ver[0]+'.'+ver[1]+'.'+ver[2]+'.'+ver[3]+' was found.');
