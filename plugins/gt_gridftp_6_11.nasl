#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59734);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2012-3292");
  script_bugtraq_id(53778);
  script_osvdb_id(82637);

  script_name(english:"Globus Toolkit GridFTP Server < 3.42 / 6.11 'getpwnam_r()' Authentication Bypass Vulnerability");
  script_summary(english:"Checks version reported in FTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is vulnerable to an authentication bypass
attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote FTP server
is running a version of GridFTP Server earlier than 3.42 / 6.11. Such
versions reportedly are affected by an authentication bypass
vulnerability caused by incorrect use of 'getpwnam_r()'. When a
'gridmap' file is improperly configured with a valid user DN mapped to
a nonexistent user account, the GridFTP server may grant access to the
client under another account.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.42 / 6.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"https://docs.globus.org/gt-jira-archive/#globus_toolkit_gt_195");
  script_set_attribute(attribute:"see_also", value:"http://lists.globus.org/pipermail/security-announce/2012-May/000019.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:globus:globus_toolkit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("gt_gridftp_detect.nasl");
  script_require_keys("Globus_Toolkit/GridFTP/Installed", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Globus Toolkit GridFTP Server";
kb = "Globus_Toolkit/GridFTP/";

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit(kb + "Installed");

# Get the ports that FTP servers have been found on, defaulting to
# what GridFTP uses in the provided configuration file.
port = get_ftp_port(default:2811);

# Get the information from the KB.
kb += port + "/";
banner = get_kb_item_or_exit(kb + "Banner");
ver = get_kb_item_or_exit(kb + "Version");

# Check if the installation is vulnerable.
if (ver =~ "^[0-3]([^0-9]|$)")
  fix = "3.42";
else
  fix = "6.11";

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);

# Generate a security report.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_hole(port:port, extra:report);
