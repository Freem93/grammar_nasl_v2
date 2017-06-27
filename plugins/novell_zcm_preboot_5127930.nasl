#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58968);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2011-3175", "CVE-2011-3176", "CVE-2012-2215");
  script_bugtraq_id(52659);
  script_osvdb_id(80230, 80231);

  script_name(english:"Novell ZENworks Configuration Management PreBoot Service Opcode Request Parsing Vulnerabilities");
  script_summary(english:"Checks version of novell-pbserv.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of ZENworks Configuration
Management installed on the remote Windows host has several
vulnerabilities in its PreBoot service :

  - An arbitrary file download vulnerability via opcode 0x21
    may allow an attacker to download any file on the remote
    system. (TID 7009969)

  - A stack-based buffer overflow vulnerability via opcode
    0x6c may allow an attacker to execute arbitrary code on
    the remote system. (TID 7009970)

  - A stack-based buffer overflow vulnerability via opcode
    0x4c may allow an attacker to execute arbitrary code on
    the remote system. (TID 7009971)");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 11.2 or apply the patch in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-800");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell ZENworks Configuration Management Preboot Service 0x4c Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8373bda8");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_detect.nasl");
  script_require_keys("SMB/Novell/ZENworks/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/Novell/ZENworks/Installed");

app = "Novell ZENworks Configuration Management PreBoot Service";

# Get details of the ZCM install.
base = get_kb_item_or_exit("SMB/Novell/ZENworks/Path");
version = get_kb_item_or_exit("SMB/Novell/ZENworks/Version");

# These issues only affect 11.1/11.1a.
if (version !~ "^11\.1([^0-9]|$)")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
path = "\bin\preboot\novell-pbserv.exe";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# Try to open the affected DLL.
fh = CreateFile(
  file:dir + path,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, app);
}

# Parse the version information from the EXE.
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);

# Clean up.
NetUseDel();

if (isnull(ver))
  exit(1, "Failed to read the version number from " + base + path + ".");

ver = join(ver, sep:".");
fix = "11.1.0.17121";

if (ver_compare(ver:ver, fix:fix) >= 0)
  exit(0, "The " + app + " install at " + base + path + " is version " + ver + " and thus not affected.");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_hole(port:port, extra:report);
