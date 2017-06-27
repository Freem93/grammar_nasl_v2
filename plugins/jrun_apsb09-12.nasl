#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70176);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2009-1873", "CVE-2009-1874");
  script_bugtraq_id(36047, 36050);
  script_osvdb_id(57186, 57187);
  script_xref(name:"EDB-ID", value:"9443");

  script_name(english:"Adobe JRun 4.0 Multiple Vulnerabilities (APSB09-12)");
  script_summary(english:"Checks the contents of web.xml in jmc-app.ear");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Adobe JRun installed that contains a
version of jmc-app.ear that is affected by multiple vulnerabilities :

  - A directory traversal vulnerability exists in
    'logviewer.jsp' in the Management Console that could
    allow an authenticated, remote attacker to read
    arbitrary files via the 'logfile' parameter.
    (CVE-2009-1873)

  - Multiple cross-site scripting vulnerabilities exist in
    the Management Console that could allow remote attackers
    to inject arbitrary web script or HTML via unspecified
    vectors. (CVE-2009-1874)");
  script_set_attribute(attribute:"see_also", value:"http://www.dsecrg.com/pages/vul/show.php?id=151");
  script_set_attribute(attribute:"see_also", value:"http://www.dsecrg.com/pages/vul/show.php?id=152");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-12.html");
  script_set_attribute(attribute:"solution", value:"Install the version of jmc-app.ear linked in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:jrun");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("jrun_installed.nasl");
  script_require_keys("SMB/Adobe_JRun/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("bsal.inc");
include("byte_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("zip.inc");

get_kb_item_or_exit("SMB/Adobe_JRun/Installed");

app = "Adobe JRun";

ver = get_kb_item_or_exit("SMB/Adobe_JRun/Version");
path = get_kb_item_or_exit("SMB/Adobe_JRun/Path");

if (ver !~ "^4\.") audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

file = path + "\servers\admin\jmc-app.ear";
ear = hotfix_get_file_contents(file);
NetUseDel();

if (ear["error"] != HCF_OK)
{
  if (ear["error"] == HCF_NOENT) audit(AUDIT_UNINST, app);
  exit(1, "Error obtaining the contents of '" + file + "'.");
}
ear = ear["data"];

war = zip_parse(blob:ear, "jmc-app.war");
if (isnull(war)) exit(1, "Error extracting 'jmc-app.war'.");

xml = zip_parse(blob:war, "WEB-INF/web.xml");
if (isnull(xml)) exit(1, "Error extracting 'web.xml'.");
xml = ereg_replace(string:xml, pattern:"\s+", replace:"");

tag =
 "<filter>" +
 "<filter-name>XSS</filter-name>" +
 "<display-name>XSS</display-name>" +
 "<description></description>" +
 "<filter-class>jrunx.jmc.filter.CrossScriptingFilter</filter-class>" +
 "</filter>";

if (tag >< xml)
  audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

security_warning(port);
