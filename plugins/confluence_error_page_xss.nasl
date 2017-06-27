#plugin_pub
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62356);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/14 15:38:18 $");

  script_bugtraq_id(55509);
  script_osvdb_id(85492);

  script_name(english:"Atlassian Confluence VelocityServlet Error Page XSS");
  script_summary(english:"Attempts to exploit a cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote server hosts an install of Atlassian Confluence that is
affected by a cross-site scripting vulnerability related to the
'ConfluenceVelocityServlet.class' and error pages.

User-supplied input in a URL is not validated properly before being
returned in an error page.  This can result in an attacker-controlled
script running in the user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Sep/68");
  # https://confluence.atlassian.com/display/DOC/Confluence+Security+Advisory+2012-09-11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b8d76fc");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-26366");
  script_set_attribute(attribute:"solution", value:"Apply the vendor patches or update to Confluence version 4.1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);


  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("confluence_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/confluence");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");


port = get_http_port(default:8080);

install = get_install_from_kb(
  appname      : 'confluence',
  port         : port,
  exit_on_fail : TRUE
);

dir = install['dir'];
install_url = build_url(port:port, qs:dir);

attack_xss = '<iframe src="javascript:alert(\''+ SCRIPT_NAME + '-' + unixtime() + '\')">';

vuln = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/pages/includes/status-list-mo'+urlencode(str:attack_xss)+'.vm',
  pass_str : "status-list-mo" + attack_xss,
  ctrl_re  : "Unable to find resource.*-mo<iframe src=.javascript:alert"
);

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Confluence", install_url);
