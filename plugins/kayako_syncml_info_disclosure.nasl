#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30053);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2008-0395");
  script_osvdb_id(40517);

  script_name(english:"Kayako SupportSuite syncml/index.php Direct Request Remote Information Disclosure");
  script_summary(english:"Requests Kayako's syncml/index.php script");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure issue.");
  script_set_attribute(attribute:"description", value:
"The version of Kayako SupportSuite installed on the remote host
returns PHP's '$_SERVER' superglobal variable in response to a request
for Kayako's 'syncml/index.php' page.  This variable contains
information about the remote web server, some of which might be
sensitive.");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-63.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486762/30/0/threaded");
  script_set_attribute(attribute:"solution", value: "Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:kayako:supportsuite");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("kayako_supportsuite_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/kayako_supportsuite", "www/PHP");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"kayako_supportsuite", port:port, exit_on_fail:TRUE)
;

dir         = install['dir'];
install_url = build_url(port:port,qs:dir);
version     = install['ver'];

# Try to exploit the issue.
url = dir + "/syncml/index.php";
r   = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);
res = r[2];

# If it's affected.
if (
  'Array' >< res &&
  egrep(pattern:"\[(DOCUMENT_ROOT|PATH|QUERY_STRING)\] =>", string:res)
)
{
  if (report_verbosity)
  {
    report = 
      "\n" +
      "Nessus was able to obtain the contents of PHP's '$_SERVER'\n" + 
      "superglobals array from the remote host using the following URL :\n" +
      "\n" +
      "  " + build_url(port: port, qs: url) + "\n";

    if (report_verbosity > 1)
    {
      report =
        report + 
        "\n" + 
        "Here are the contents :\n" +
        "\n" +
        res;
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Kayako SupportSuite", install_url, version);
