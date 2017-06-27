#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88881);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:05:36 $");

  script_cve_id("CVE-2016-1914", "CVE-2016-1915");
  script_osvdb_id(134674, 134675, 134676);

  script_name(english:"BlackBerry Enterprise Service Multiple Vulnerabilities (BSRT-2016-001)");
  script_summary(english:"Checks the version of BlackBerry Enterprise Service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the BlackBerry Enterprise Service (BES)
install on the remote host is older than 12.4, it is, therefore,
affected by the following vulnerabilities:

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input to the 'ImageName'
    parameter in the com.rim.mdm.ui.server.ImageServlet
    servlet. A remote attacker can exploit this, by
    convincing a user to click a specially crafted link, to
    inject or manipulate SQL queries to the back-end
    database, resulting in the manipulation or disclosure or
    arbitrary data. (CVE-2016-1914)

  - Multiple cross-site scripting vulnerabilities exist due
    to improper sanitization of user-supplied input to the
    'locale' parameter in the index.jsp and loggedOut.jsp
    scripts. A remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-1915)");
  script_set_attribute(attribute:"see_also", value:"http://support.blackberry.com/kb/articleDetail?articleNumber=000038033");
  script_set_attribute(attribute:"solution", value:
"Update to BlackBerry Enterprise Service version 12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_enterprise_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "BlackBerry_ES/Product");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

product = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
path = get_kb_item_or_exit("BlackBerry_ES/Path");

if ("BlackBerry Enterprise Service" >!< product)
  audit(AUDIT_NOT_INST, "BlackBerry Enterprise Service");

fix = "12.4";
# Fix and affected are different: 12.4 vs 12.3.1. Possible for
# releases after 12.3.1, but not probable.
if (version =~ "^12\." && (ver_compare(ver:version, fix:"12.3.1", strict:FALSE) <= 0))
{
  set_kb_item(name: 'www/0/XSS', value: TRUE);
  set_kb_item(name: 'www/0/SQLInjection', value: TRUE);

  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report =
    '\n  Product              : ' + product +
    '\n  Path                 : ' + path +
    '\n  Installed version    : ' + version +
    '\n  Fixed version        : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, "BlackBerry Enterprise Service", version, path);
