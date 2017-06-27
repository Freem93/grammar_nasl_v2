#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69099);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2007-5394", "CVE-2007-6021", "CVE-2007-6432");
  script_bugtraq_id(31975, 31999);
  script_osvdb_id(50054, 50055, 50056);

  script_name(english:"Adobe PageMaker 7.0.1 / 7.0.2 Multiple Vulnerabilities (APSA08-10)");
  script_summary(english:"Checks version of AldFs32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Adobe PageMaker installed that
contains a version of AldFs32.dll that is affected by multiple code
execution vulnerabilities :

  - A heap-based buffer overflow exists that could allow
    remote attackers to execute arbitrary code via malformed
    .PMD files. (CVE-2007-6021)

  - Multiple stack-based buffer overflow vulnerabilities
    exist that could allow remote attackers to execute
    arbitrary code via malformed .PMD files. (CVE-2007-5394,
    CVE-2007-6432)");
  script_set_attribute(attribute:"solution", value:"Install the version of AldFS32.dll linked in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa08-10.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:pagemaker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_pagemaker_installed.nasl");
  script_require_keys("SMB/Adobe_PageMaker/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Adobe_PageMaker/Installed");

app = "Adobe PageMaker";

# Pull install info from the KB.
kb_base = "SMB/Adobe_PageMaker/";
version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

# Only 7.0.1 and 7.0.2 are affected.
if (version !~ "^7\.0\.[12](\.|$)")
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

name   = kb_smb_name();
port   = kb_smb_transport();
#if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

# Try to connect to the server.
#soc = open_sock_tcp(port);
#if (!soc) audit(AUDIT_SOCK_FAIL, port);
#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


path = ereg_replace(string:path, pattern:"^(.+)\\$", replace:"\1");
share = hotfix_path2share(path:path);
exe = path + "\AldFs32.dll";

# Connect to the share the application is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# Open the DLL file.
fh = CreateFile(
  file:ereg_replace(string:exe, pattern:"^[A-Za-z]:(.*)", replace:"\1"),
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_VER_FAIL, exe);
}

# Parse the PE header.
ret = GetFileVersionEx(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ret) || isnull(ret["dwTimeDateStamp"]))
  exit(1, "Failed to get the timestamp of '" + exe + "'.");

timestamp = ret["dwTimeDateStamp"];
fixed = 1210085114;

if (timestamp >= fixed)
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  File              : ' + exe +
    '\n  File timestamp    : ' + timestamp +
    '\n  Fixed timestamp   : ' + fixed +
    '\n';
}

security_hole(port:port, extra:report);
