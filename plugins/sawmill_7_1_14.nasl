#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19681);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2005-2950");
  script_bugtraq_id(14789);
  script_osvdb_id(19254);

  script_name(english:"Sawmill < 7.1.14 GET Request Query String XSS");
  script_summary(english:"Checks for cross-site scripting vulnerability in Sawmill < 7.1.14.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a
cross-site scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of Sawmill running on the remote web server is affected by
a cross-site scripting vulnerability due to improper validation of
user-supplied input appended to a GET request. An unauthenticated,
remote attacker can exploit this, via a specially crafted request, to
execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Sep/113");
  # https://web.archive.org/web/20061218222748/http://www.nta-monitor.com/posts/2005/09/sawmill.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55a77b2f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sawmill version 7.1.14 or later. Alternatively, use Sawmill
in CGI mode.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sawmill:sawmill");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl","sawmill_detect.nasl");
  script_require_ports("Services/www", 8987, 8988);
  script_require_keys("installed_sw/Sawmill");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Sawmill";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8988, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# A simple alert.
xss = "<script>alert('" +SCRIPT_NAME - ".nasl"+"-"+unixtime()+ "')</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

# The flaw only affects Sawmill's built-in web server.
banner = get_http_banner(port:port);
if (banner && "Server: Sawmill/" >< banner)
{
  url = dir + "/?" + rand_str() + "=" + exss;
  w = http_send_recv3(method:"GET",
    item:url,
    port:port, exit_on_fail:TRUE
  );
  res = w[2];

  # There's a problem if we see our XSS.
  if (xss >< res)
  {
    output = strstr(res, xss);
    if (empty_or_null(output)) output = res;

    security_report_v4(
      port       : port,
      severity   : SECURITY_WARNING,
      generic    : TRUE,
      xss        : TRUE,  # XSS KB key
      request    : make_list(build_url(qs:url, port:port)),
      output     : output
    );
    exit(0);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
}
else audit(AUDIT_WRONG_WEB_SERVER, port, app);
