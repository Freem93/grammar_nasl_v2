#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55670);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2011-0287");
  script_bugtraq_id(48655);
  script_osvdb_id(73868);
  script_xref(name:"Secunia", value:"45242");

  script_name(english:"BlackBerry Enterprise Server Administration API Unspecified Remote Vulnerability (KB27258)");
  script_summary(english:"Checks version and looks for workaround.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
vulnerability that can result in information disclosure and partial
denial of service.");
  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host
reportedly contains a vulnerability in its administrator API. By
exploiting this vulnerability, an attacker may be able to read files
stored on the BlackBerry Enterprise Server that contain only printable
characters or exhaust the resources on the server resulting in denial
of service.");

  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB27258");

  script_set_attribute(attribute:"solution", value:
"Install the Interim Security Software Update for July 12th 2011, or
upgrade to at least 5.0.1 MR4 for Novell GroupWise / 5.0.3 MR3 for IBM
Lotus Domino / 5.0.3 MR3 for Microsoft Exchange.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("bsal.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("zip.inc");
include("audit.inc");

# Skip versions that aren't vulnerable. The KB article isn't as clear
# as the release notes. The latter states that the vulnerable versions
# are:
#   BES for Microsoft Exchange : 5.0 SP1, 5.0 SP2, 5.0 SP3
#   BES for IBM Lotus Domino   : 5.0 SP1, 5.0 SP2, 5.0 SP3
#   BES for Novell GroupWise   : 5.0 SP1
#
# And the versions that include the fix are:
#   BES for Microsoft Exchange : 5.0 SP3 MR3
#   BES for IBM Lotus Domino   : 5.0 SP3 MR3
#   BES for Novell GroupWise   : 5.0 SP1 MR4
not_vuln = FALSE;
pattern = "^5\.0\.([0-3])(?: MR ([0-9]+))? ";
prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
if ("Enterprise Server" >!< prod)
{
  not_vuln = TRUE;
}
else if (version !~ "^5\.0\.[1-3] ")
{
  not_vuln = TRUE;
}
else if ("Microsoft Exchange" >< prod)
{
  matches = eregmatch(string:version, pattern:pattern);
  if (
    !isnull(matches) &&
    (matches[1] == 3 && !isnull(matches[2]) && matches[2] >= 3)
  ) not_vuln = TRUE;
}
else if ("IBM Lotus Domino" >< prod)
{
  matches = eregmatch(string:version, pattern:pattern);
  if (
    !isnull(matches) &&
    (matches[1] == 3 && !isnull(matches[2]) && matches[2] >= 3)
  ) not_vuln = TRUE;
}
else if ("Novell GroupWise" >< prod)
{
  matches = eregmatch(string:version, pattern:pattern);
  if (
    !isnull(matches) &&
    ((matches[1] > 1) ||
     (matches[1] == 1 && !isnull(matches[2]) && matches[2] >= 4))
  ) not_vuln = TRUE;
}
else
{
  exit(0, prod + " is not on a recognized platform.");
}

if (not_vuln) exit(0, prod + " " + version + " is not vulnerable.");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Split the software's location into components.
base = get_kb_item_or_exit("BlackBerry_ES/Path");
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
path = "\BAS\jboss\ejb\server\default\lib\jbossws-common.jar";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

fh = CreateFile(
  file:dir + path,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  manifest = zip_parse(smb:fh, "META-INF/MANIFEST.MF");
  CloseFile(handle:fh);
}

# Clean up.
NetUseDel();

# Get the manifest.
if (isnull(manifest)) exit(1, "Failed to read manifest from " + base + path + ".");

# Extract version of JAR file.
line = egrep(string:manifest, pattern:"^Implementation-Version:");
if (!(line)) exit(1, "Failed to read implementation version from manifest.");

matches = eregmatch(string:line, pattern:"Implementation-Version: ([^ ]+) \(build=([0-9]+)\)");
if (isnull(matches)) exit(1, "Failed to parse implementation version from manifest.");
ver = matches[2];

# Determine what the version should be.
if (prod =~ "(Microsoft Exchange|IBM Lotus Domino)")
  fix = "201104121234";
else
  fix = "201104121341";

# Check if fix is installed.
if (ver >= fix)
  exit(0, prod + " " + version + " on the remote host has been fixed and is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Product              : ' + prod +
    '\n  Path                 : ' + base +
    '\n  Installed version    : ' + version +
    '\n' +
    '\nBased on its build date, ' + base + path + ' needs to be updated.' +
    '\n' +
    '\n  Installed build date : ' + ver +
    '\n  Fixed build date     : ' + fix +
    '\n' +
    '\nInstall Interim Security Software Update for July 12th 2011 to correct the issue.' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
