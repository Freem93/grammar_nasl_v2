#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: Seth Woolley <seth@tautology.org>
# To: bugtraq@securityfocus.com
# Cc: full-disclosure@lists.netsys.com
# Subject: Cafelog WordPress / b2 SQL injection vulnerabilities discovered and
#   fixed in CVS

include("compat.inc");

if (description)
{
  script_id(11866);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_bugtraq_id(8756);
  script_osvdb_id(4609);

  script_name(english:"WordPress 'blog.header.php' Multiple Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection in wordpress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a blog with multiple SQL injection
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress running on the remote host is affected by
multiple SQL injection vulnerabilities. An attacker can exploit these
flaws to execute arbitrary database queries resulting in the
disclosure of sensitive information.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Oct/index.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.72 RC1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencie("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

url = "/index.php?cat='";
r = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

if(egrep(pattern:"SQL.*post_date <=", string:r))
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
