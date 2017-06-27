#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63476);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2012-6272");
  script_bugtraq_id(57212);
  script_osvdb_id(89071);
  script_xref(name:"TRA", value:"TRA-2013-01");
  script_xref(name:"CERT", value:"950172");
  
  script_name(english:"Dell OpenManage Server Administrator index_main.htm DOM-based XSS");
  script_summary(english:"Requests PoC URL");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote web server has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Dell OpenManage Server Administrator hosted on the
remote web server has a cross-site scripting vulnerability.  Making a
specially crafted request for index_main.htm can result in client-side
script injection.  An attacker could exploit this by tricking a user
into requesting a maliciously crafted URL."
  );
  script_set_attribute(
    attribute:"solution",
    value:"There is no known solution at this time."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-01");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:openmanage_server_administrator");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("dell_openmanage.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/dell_omsa");
  script_require_ports("Services/www", 1311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:1311, embedded:TRUE);
install = get_install_from_kb(appname:'dell_omsa', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);

poc_url = install['dir'] + '/help/sm/en/Output/wwhelp/wwhimpl/js/html/index_main.htm?topic="></iframe><iframe src="javascript:alert(/xss/)';
res = http_send_recv3(method:'GET', item:poc_url, port:port, exit_on_fail:TRUE);

# This is currently unpatched, but the patch for a similar vulnerability in a recent version
# redirects to a different page when a malicious URL is requested
#hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
#if (hdrs['$code'] == 302)
#  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Dell OpenManage Server Administrator', base_url);

# Make sure evidence of the DOM XSS is present before flagging as vulnerable.
# gup() contains the underlying vulnerability, it is called by getTopic(), which is called by the onload attribute of the <body> tag
if ('function gup' >!< res[2] || 'function getTopic' >!< res[2] || 'onload="getTopic()"' >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Dell OpenManage Server Administrator', base_url);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report = get_vuln_report(port:port, items:poc_url);
  security_warning(port:port, extra:report);
}
else security_warning(port);
