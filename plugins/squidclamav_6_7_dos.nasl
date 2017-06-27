#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62031);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_cve_id("CVE-2012-3501");
  script_bugtraq_id(54663);
  script_osvdb_id(84138);

  script_name(english:"SquidClamav Specially Crafted Character Parsing Remote DoS");
  script_summary(english:"Tests url parameter for escaped > character");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is affected by a remote
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SquidClamav installed on the remote host is affected by
a remote denial of service (DoS) vulnerability because it fails to
properly escape URL's in system command calls.  Specially crafted URL's
with characters such as %0D or %0A can cause the daemon to crash.");
  # https://github.com/darold/squidclamav/commit/5806d10a31183a0b0d18eccc3a3e04e536e2315b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a9d0663");
  script_set_attribute(attribute:"see_also", value:"http://squidclamav.darold.net/news.html");
  script_set_attribute(attribute:"solution", value:"Update to version 5.8 / 6.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:darold:squidclamav");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("squidclamav_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/squidclamav");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "squidclamav",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
page = '/clwarn.cgi';
test_dos = '>' + SCRIPT_NAME;
url = page + '?url=' + test_dos;

res = http_send_recv3(method:"GET", item:dir + url, port:port, exit_on_fail:TRUE);
loc = build_url(qs:dir, port:port);

# Patched versions will escape the > and use &gt;
if (
  'URL ' + test_dos  >< res[2] || 
  '"color: #0000FF">'+ test_dos + '</h3>'>< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists with the following request : ' +
      '\n' +
      '\n  ' + loc + url +
      '\n' +
      '\nNote that you can view the source of the page in your browser to verify' +
      '\nthat the greater than character (">") is not encoded.' +
      '\n';

    security_warning(port:port, extra:report);
    exit(0);
  }
  else security_warning(port:port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "SquidClamav", loc + page);
