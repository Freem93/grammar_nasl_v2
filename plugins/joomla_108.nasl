#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21143);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2006-1027");
  script_bugtraq_id(88070);
  script_osvdb_id(23815);

  script_name(english:"Joomla! < 1.0.8 Information Disclosure");
  script_summary(english:"Checks for path disclosure issue in Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! installed on the remote web server is affected
by an information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, via a specially crafted request, to
disclose the full path information from the Joomla! installation.

Note that the application is reportedly affected by additional
vulnerabilities, including a denial of service vulnerability, multiple
unspecified SQL injection vulnerabilities, and additional information
disclosure vulnerabilities; however, Nessus has not tested for these
issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426538");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Mar/49");
  # https://www.joomla.org/announcements/release-news/940-joomla-108-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4ae9333");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# Try to get the full path.
# the trailing slash prevents a file from being created in
# Joomla's cache directory.
url = dir + "/index.php?option=com_rss&feed=" +SCRIPT_NAME+ "/&no_html=1";
w = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if the file can't be created.
#
# nb: 1.0.8 reports "You are not authorized to view this resource."
if ("Error creating feed file, please check write permissions" >< res)
{
  output = strstr(res, "Error creating feed file");
  if (empty_or_null(output)) output = res;

  security_report_v4(
    port       : port,
    generic    : TRUE,
    severity   : SECURITY_WARNING,
    line_limit : 3,
    request    : make_list(build_url(qs:url, port:port)),
    output     : output,
    sqli       : TRUE
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
