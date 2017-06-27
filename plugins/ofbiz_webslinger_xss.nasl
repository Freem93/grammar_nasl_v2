#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59248);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");

  script_cve_id("CVE-2012-1621");
  script_bugtraq_id(53023);
  script_osvdb_id(81346, 81347, 81348, 81349);

  script_name(english:"Apache OFBiz Webslinger Component XSS");
  script_summary(english:"Attempts a reflected XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web application has a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Webslinger (included with Apache OFBiz) hosted on the
remote host has a cross-site scripting vulnerability.  A remote
attacker could exploit this by tricking a user into requesting a
specially crafted URL, resulting in arbitrary script code execution. 
This version of OFBiz reportedly has other vulnerabilities, though
Nessus has not tested for those issues."
  );
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2012/Apr/172");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apache OFBiz 10.04.02 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/04/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:open_for_business_project");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ofbiz_detect.nasl");
  script_require_ports("Services/www", 8443);
  script_require_keys("www/ofbiz/port");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");
include("audit.inc");

port = get_kb_item_or_exit('www/ofbiz/port');
webslinger_dir = '/webslinger';
xss = '<script>alert(/' + SCRIPT_NAME + '/)</script>';
url = webslinger_dir + '/' + xss;
expected_output = 'The file (/' + xss + ') was missing';

# can't use test_cgi_xss() since the PoC results in a 404
res = http_send_recv3(method:'GET', item:url, port:port, fetch404:TRUE, exit_on_fail:TRUE);
if (expected_output >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'OFBiz', build_url(qs:'', port:port));
else
  set_kb_item(name:'www/' + port + '/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report = get_vuln_report(items:url, port:port);
  security_warning(port:port, extra:report);
}
else security_warning(port:port, extra:report);
