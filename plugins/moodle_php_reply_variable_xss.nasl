#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14257);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2004-1711");
  script_bugtraq_id(10884);
  script_osvdb_id(8383);

  script_name(english:"Moodle 'post.php' 'reply' Parameter XSS");
  script_summary(english:"Determines if Moodle is vulnerable to 'post.php' XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle on the remote host contains a flaw that allows a
remote cross-site scripting attack due to the application not properly
validating the 'reply' variable on submission to the 'post.php'
script.

This allows a user to create a specially crafted URL that would
execute arbitrary code in a user's browser within the trust
relationship between the browser and the server, leading to a loss of
integrity.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/93");
  script_set_attribute(attribute:"solution", value:"Upgrade to Moodle 1.4 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/post.php?reply=<script>document.write('Nessus plugin to detect post.php flaw');</script>",
  exit_on_fail : TRUE
);

if (ereg(pattern:"Nessus plugin to detect post.php flaw", string:res[2]))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
