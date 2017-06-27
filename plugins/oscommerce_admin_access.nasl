#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19253);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_name(english:"osCommerce Unprotected Admin Directory");
  script_summary(english:"Checks for unprotected admin directory in osCommerce");

  script_set_attribute(attribute:"synopsis", value:
"The remote web host contains a PHP application that can be
administered by anyone." );
  script_set_attribute(attribute:"description", value:
"The installation of osCommerce on the remote host apparently lets
anyone access the application's admin directory, which means that they
have complete administrative access to the site." );
  script_set_attribute(attribute:"see_also", value:"http://www.oscommerce.info/docs/english/e_post-installation.html");
  script_set_attribute(attribute:"solution", value:
"Limit access to the directory using Apache's .htaccess or an
equivalent technique." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/oscommerce");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install.
install = get_install_from_kb(appname:'oscommerce', port:port);
if (isnull(install)) exit(1, "osCommerce wasn't detected on port "+port+".");
dir = install['dir'];


# Request 'admin/index.php'.
url = string(dir, "/admin/index.php");

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# There's a problem if it looks like we got into the admin interface.
if (egrep(pattern:"/admin/customers\.php\?selected_box=customers[^>]*>Customers<", string:res[2]))
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to access the admin directory using the following\n",
      "URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The osCommerce install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
