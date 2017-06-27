#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44941);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2010-5188");
  script_bugtraq_id(38394);
  script_osvdb_id(62542);
  script_xref(name:"Secunia", value:"38697");

  script_name(english:"SilverStripe debug_profile Parameter Information Disclosure");
  script_summary(english:"Attempts to access unauthorized data");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server is hosting a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description",value:
"The SilverStripe CMS install hosted on the remote web server is
affected by an information disclosure vulnerability because it fails to
properly handle the 'debug_profile' parameter of the 'sapphire/main.php'
script when running in live mode.

An attacker, exploiting this flaw, can gain sensitive debugging
information related to the running application.

Note that the installed version is potentially affected by other
vulnerabilities, though Nessus has not tested for those.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5585847c");
  script_set_attribute(attribute:"see_also",value:"http://open.silverstripe.org/wiki/ChangeLog/2.3.6");
  script_set_attribute(attribute:"solution", value:"Upgrade to SilverStripe 2.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:silverstripe:silverstripe");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("silverstripe_detect.nasl", "silverstripe_dev_mode.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/silverstripe");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php: 1);

install = get_install_from_kb(appname:'silverstripe', port:port);
if (isnull(install)) exit(1, "SilverStripe CMS wasn't detected on port "+port+".");

# Make sure the system is not in dev mode.
dev = get_kb_item('www/silverstripe'+install['dir']+'/dev');
if (!isnull(dev)) exit(0, "The SilverStripe install at "+build_url(qs:install['dir'], port:port)+" is running in dev mode.");

# Attempt to exploit the vulns.
url = install['dir'] + "/?debug_profile=1";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

if (
  res[2] &&
  "Click to close)</a></p><pre>" >< res[2] &&
  "PROFILER OUTPUT" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to verify the issue with the following request :\n' +
      '\n' +
      crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
      '  ' + build_url(port:port, qs:url) + '\n' +
      crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n';
    if (report_verbosity > 1)
    {
      output = strstr(res[2], "(Click to close)</a></p><pre>") - res[2];
      report +=
        '\n' +
        'It produced the following output :\n' +
        '\n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
        output + '\n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else exit(0, "The SilverStripe CMS install at " + build_url(qs:install['dir']+'/', port:port) + " is not affected.");
