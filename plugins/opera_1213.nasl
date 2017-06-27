#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64363);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2013-1618", "CVE-2013-1637", "CVE-2013-1638", "CVE-2013-1639");
  script_bugtraq_id(57633, 57773);
  script_osvdb_id(89614, 89615, 89616, 89848);
  script_xref(name:"EDB-ID", value:"24448");

  script_name(english:"Opera < 12.13 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:

"The version of Opera installed on the remote host is earlier than 12.13
and is, therefore, reportedly affected by the following 
vulnerabilities :

  - An error exists related to DOM manipulation that could
    lead to application crashes or arbitrary code
    execution. (1042)

  - A use-after-free error exists related to SVG 'clipPaths'
    that could lead to memory corruption or arbitrary code
    execution. (1043)

  - An error exists related to the TLS protocol, CBC mode
    encryption and response time. An attacker could obtain
    plaintext contents of encrypted traffic via timing
    attacks. (1044)

  - The application could fail to make the proper 'pre-
    flight' Cross-Origin Resource Sharing (CORS) requests.
    In some situations this error could aid an attacker in
    cross-site request forgery (CSRF) attacks. (1045)

  - An unspecified, low severity issue exists that has an
    unspecified impact.");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1042/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1043/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1044/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1045/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/unified/1213/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37c158d3");
  script_set_attribute(attribute:"see_also", value:"http://www.isg.rhul.ac.uk/tls/");
  script_set_attribute(attribute:"solution", value: "Upgrade to Opera 12.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");
path = get_kb_item_or_exit("SMB/Opera/Path");

version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "12.13.1734.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.13")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.13";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
