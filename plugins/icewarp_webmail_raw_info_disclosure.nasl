#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63304);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_bugtraq_id(55507);
  script_osvdb_id(85498);

  script_name(english:"IceWarp Webmail raw.php Information Disclosure");
  script_summary(english:"Attempts to view phpinfo() output");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IceWarp installed on the remote host is affected by an
information disclosure vulnerability.  A remote, unauthenticated
attacker may be able to view PHP configuration information via the
phpinfo() function by requesting the webmail/pda/controller/raw.php
script.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("icewarp_webmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/icewarp_webmail");
  script_require_ports("Services/www", 32000, 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:32000);

install = get_install_from_kb(
  appname      : "icewarp_webmail",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
loc = build_url(port:port, qs:dir);

url = "/pda/controller/raw.php";

res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : dir + url,
  exit_on_fail : TRUE
);

if ("<title>phpinfo()</title>" >< res[2])
{
  out = strstr(res[2], "<title>");
  count = 0;
  foreach line (split(out))
  {
    output += line;
    count++;
    if (count >= 15) break;
  }

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue with the following URL' +
      '\n' +
      '\n' + loc + url +
      '\n';

    if (report_verbosity > 1)
    {
      snip = crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);

      report +=
        '\n' + 'This produced the following truncated output :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "IceWarp Webmail", loc + "/");
