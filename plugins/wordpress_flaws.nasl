#
# (C) Tenable Network Security, Inc.
#

# ref: http://www.kernelpanik.org/docs/kernelpanik/wordpressadv.txt

include("compat.inc");

if (description)
{
  script_id(11703);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2014/11/01 00:22:04 $");

  script_cve_id("CVE-2003-1599");
  script_bugtraq_id(7785);
  script_osvdb_id(4610, 4611);

  script_name(english:"WordPress < 0.72 RC1 Multiple Vulnerabilities");
  script_summary(english:"Tests for injection attacks.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that allow for arbitrary
PHP code execution and local file disclosure as well as SQL injection
attacks.");
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files hosted on a
third-party server using the WordPress CGI suite that is installed
(which is also vulnerable to a SQL injection attack).

An attacker may use this flaw to inject arbitrary PHP code into the
remote host and gain a shell with the privileges of the web server or
to take the control of the remote database.");
  script_set_attribute(attribute:"see_also", value:"http://www.kernelpanik.org/docs/kernelpanik/wordpressadv.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to 0.72 RC1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

  script_dependencie("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
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

function check_php_inc(loc)
{
  local_var r, w;
  w = http_send_recv3(
    method:"GET",
    item:loc + "/wp-links/links.all.php?abspath=http://xxxxxxxx",
    port:port,
    exit_on_fail:TRUE
  );
  r = w[2];
  if("http://xxxxxxxx/blog.header.php" >< r)
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    security_hole(port);
    exit(0);
  }
}

function check_sql_inj(loc)
{
  local_var r, w;
  w = http_send_recv3(
    method:"GET",
    item:loc + "/index.php?posts='",
    port:port,
    exit_on_fail:TRUE
  );
  r = w[2];
  if("mysql_fetch_object()" >< r)
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    security_hole(port);
    exit(0);
  }
}

# Test an install.
install = get_single_install(
  app_name : app,
  port     : port
);

loc = install['path'];
install_url = build_url(port:port, qs:loc);

check_php_inc(loc:loc);
check_sql_inj(loc:loc);

audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
