#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40493);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(35855);
  script_osvdb_id(56602);
  script_xref(name:"EDB-ID", value:"9296");
  script_xref(name:"Secunia",value:"36031");

  script_name(english:"TinyBrowser Multiple XSS");
  script_summary(english:"Checks for an XSS flaw in upload.php.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"TinyBrowser, an open source web file browser, is running on the remote
host. TinyBrowser is typically bundled with web applications, such as
TinyMCE WYSIWYG content editor or the Joomla! content management
system, although it can also be used in its standalone configuration
or integrated with other custom web applications.

The version of the TinyBrowser component running on the remote host is
affected by multiple cross-site scripting (XSS) vulnerability in
/tinybrowser/upload.php due to improper sanitization of user-supplied
input to the 'goodfiles', 'badfiles' and 'dupfiles' parameters before
using it to generate dynamic HTML content. An unauthenticated, remote
attacker can exploit these to inject arbitrary HTML and script code
into the user's browser session.

Note that this version of TinyBrowser may be affected by several other
vulnerabilities that allow an unauthenticated user to view, upload,
delete, and rename files and folders on the affected host, or to
launch cross-site request forgery attacks using the application.
However, Nessus has not checked for these.");
  # http://yehg.net/lab/pr0js/advisories/tinybrowser_1416_multiple_vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb00c05f");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Jul/462");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Jul/464");
  script_set_attribute(attribute:"solution", value:
"It could not be determined if TinyBrowser is used in a standalone
configuration. If used with Joomla! 1.5.12, upgrade to Joomla! version
1.5.13.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

joomla = make_list();
joomla_installs = get_installs(
  app_name : "Joomla!",
  port     : port
);

if (joomla_installs[0] == IF_OK)
{
  foreach install (joomla_installs[1])
  {
    dir = install['path'];
    joomla = make_list(dir, joomla);
  }
}

joomla_dirs = make_list();
foreach dir (joomla)
{
  joomla_dirs = make_list(joomla_dirs, dir + "/plugins/editors/tinymce/jscripts/tiny_mce/plugins");
}

if (thorough_tests)
{
  dirs = list_uniq(make_list(
    "/tinymce3/jscripts/tiny_mce/plugins",
    "/tiny_mce/plugins",
    "/plugins/editors/tinymce/jscripts/tiny_mce/plugins",
    "/tinymce/jscripts/tiny_mce/plugins",
    cgi_dirs())
  );
  dirs = list_uniq(make_list(dirs, joomla_dirs));
}
else
  dirs = make_list(cgi_dirs());

non_affect = make_list();
info = "";
vuln = FALSE;

foreach dir (dirs)
{
  dir = dir + "/tinybrowser";

  xss = '1><script>alert('+"'"+SCRIPT_NAME - ".nasl"+"'"+')</script>';
  exploit = dir + "/upload.php?badfiles=" + xss;

  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : exploit,
    exit_on_fail : TRUE
  );

  if (thorough_tests && xss >!< res[2])
  {
    exploit = dir + "/upload.php?goodfiles=" + xss;
    res = http_send_recv3(
      port   : port,
      method : "GET",
      item   : exploit,
      exit_on_fail : TRUE
    );

    if(xss >!< res[2])
    {
      exploit = dir + "/upload.php?dupfiles=" + xss;
      res = http_send_recv3(
        port   : port,
        method : "GET",
        item   : exploit,
        exit_on_fail : TRUE
      );
    }
  }
  if (res[0] !~ "^HTTP/[0-9.]+ 200 ") continue;

  if (
     ('div class="alertfailure">'+xss >< res[2] && '>Upload Files<' >< res[2])
     ||
     ('div class="alertsuccess">'+xss >< res[2] && '>Upload Files<' >< res[2])
    )
  {
    output = strstr(res[2], xss);
    if (empty_or_null(output)) output = res[2];

    info += "  " + build_url(qs:exploit, port:port) + '\n';
    vuln = TRUE;
  }
  non_affect = make_list(non_affect, dir);
  if (!thorough_tests) break;
}

if (vuln)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    xss         : TRUE,
    generic     : TRUE,
    request     : split(info),
    output      : chomp(output)
  );
  exit(0);
}
else
{
  installs = max_index(non_affect);
  if (installs == 0)
    exit(0, "None of the urls (" + join(dirs, sep:" & ") + ") on port " + port+ " are affected");

  else if (installs == 1)
    exit(0, "The url tested (" + build_url(qs:dir, port:port)+ ") is not affected.");

  else exit(0, "None of the urls (" + join(non_affect, sep:" & ") + ") on port " + port + " are affected.");
}
