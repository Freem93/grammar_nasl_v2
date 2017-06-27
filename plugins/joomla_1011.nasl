#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22297);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2006-4468");
  script_bugtraq_id(19749);
  script_osvdb_id(28339, 28343);

  script_name(english:"Joomla! < 1.0.11 administrator/index.php Input Weakness");
  script_summary(english:"Checks if input to Joomla's administrator page is sanitized.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an input sanitization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! installed on the remote host is affected by an
input weakness flaw in the administrator/index.php script due to
improper sanitization of user-supplied input. An unauthenticated,
remote attacker can exploit this to impact confidentiality, integrity,
or availability. No other details are available.

Note that Joomla! is reportedly affected by additional
vulnerabilities; however, Nessus has not tested for these.");
  # http://web.archive.org/web/20080701014536/http://www.joomla.org/content/view/1843/74/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6f8af3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.0.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/01");

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
test_script = SCRIPT_NAME - ".nasl";
# Make sure input is sanitized to the index2.php script.
#
# nb: if globals.php is included, it will complain because GLOBALS is protected.
url1 = dir + "/administrator/index2.php?GLOBALS=" + test_script;
w = http_send_recv3(
  method : "GET",
  item   : url1,
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# If it does...
if ("Illegal variable" >!< res)
{
  url2 = dir + "/administrator/index.php?GLOBALS=" + test_script;
  # See whether index.php calls globals.php.
  w = http_send_recv3(
    method : "GET",
    item   : url2,
    port   : port,
    exit_on_fail : TRUE
  );
  res = w[2];

  if ("Illegal variable" >< res)
  {
    security_report_v4(
      port     : port,
      generic  : TRUE,
      severity : SECURITY_WARNING,
      request  : make_list(build_url(qs:url1, port:port), build_url(qs:url2, port:port)),
      output   : chomp(res)
    );
    exit(0);
  }
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
