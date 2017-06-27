#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73291);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/01 18:42:37 $");

  script_cve_id("CVE-2014-0818", "CVE-2014-0819");
  script_bugtraq_id(65745, 65749);
  script_osvdb_id(103584, 103585);

  script_name(english:"Autodesk AutoCAD < 2014 Multiple Vulnerabilities");
  script_summary(english:"Checks Autodesk AutoCAD version");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Autodesk AutoCAD installed prior to
AutoCAD 2014. It is, therefore, potentially affected by the following
vulnerabilities :

  - An error exists related to handling FAS files that
    could allow execution of arbitrary VBScript code.
    (CVE-2014-0818)

  - An error exists related to dynamic library loading.
    The application insecurely looks in the current working
    directory when resolving DLL dependencies. Attackers may
    exploit the issue by placing a specially crafted DLL
    file and another file associated with the application in
    a location controlled by the attacker. When the
    associated file is launched, the attacker's arbitrary
    code can be executed. (CVE-2014-0819)");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN43254599/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN33382534/index.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Autodesk AutoCAD 2014 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("SMB/Autodesk AutoCAD/Installed");
  exit(0);

}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Autodesk AutoCAD/Installed");
installs = get_kb_list_or_exit("SMB/Autodesk AutoCAD/*/Version");
kb_entry = branch(keys(installs));
kb_base = kb_entry - "/Version";

version = get_kb_item_or_exit(kb_entry);
path    = get_kb_item_or_exit(kb_base + "/Path");
flavor  = get_kb_item_or_exit(kb_base + "/Flavor");
display_name = get_kb_item_or_exit(kb_base + "/Display_Name");

sp  = get_kb_item(kb_base + "/SP");
if (isnull(sp)) sp = '';
else sp = ' ' + sp;

if (flavor != "Normal") audit(AUDIT_INST_VER_NOT_VULN, display_name + sp);

# Affected :
# AutoCAD before 2014 (19.1 version number)
if (version =~ "^R([0-9]|1[0-8]|19\.0)($|[^0-9])")
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report += '\n  Product           : ' + display_name + sp +
              '\n  Path              : ' + path +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : R19.1 (Autodesk AutoCAD 2014)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, display_name + sp, version, path);
