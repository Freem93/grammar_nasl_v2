#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65984);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_bugtraq_id(58281);
  script_osvdb_id(90839);

  script_name(english:"Cerb Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cerb");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server contains 
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Cerb installed on the remote host is earlier than
6.2.5. It is, therefore, affected by multiple vulnerabilities:

  - A flaw exists in that the application does not validate
    input passed via HTML email attachments, making it 
    vulnerable to XSS.  An attacker could exploit this 
    issue to inject arbitrary HTML and script code into a
    user's browser to be executed within the security
    context of the affected site.

  - A flaw exists in the 'Remember me' cookie for the login
    process that could potentially disclose information to 
    a malicious script in a browser."); 
  script_set_attribute(attribute:"see_also", value:"http://wiki.cerbweb.com/6.2#6.2.5");
# https://wgmdev.atlassian.net/browse/CHD-3285
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?535bc8ce");
# https://wgmdev.atlassian.net/browse/CHD-3286
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c5ab580");
  script_set_attribute(attribute:"solution", value:"Update to Cerb 6.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberus:cerberus_helpdesk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cerberus_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cerb", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"cerb", port:port, exit_on_fail:TRUE);

dir = install["dir"];
version = install["ver"];

if(version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, 'Cerb', port);
loc =  build_url(port:port, qs:dir);
fix = "6.2.5";

ver = split(version, sep:'.', keep:FALSE);

if ( (ver[0] < 6) || 
     (ver[0] == 6 && ver[1] < 2) || 
     (ver[0] == 6 && ver[1] == 2 && ver[2] < 5)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cerb", loc, version);
