#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77238);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/06/23 19:48:37 $");

  script_cve_id("CVE-2014-5197", "CVE-2014-5198");
  script_bugtraq_id(69234);
  script_osvdb_id(109851, 109852);

  script_name(english:"Splunk Enterprise 6.1.x < 6.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the Splunk Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Splunk Enterprise hosted on the
remote web server is 6.1.x prior to 6.1.3. It is, therefore, affected
by the following vulnerabilities :

  - A path traversal vulnerability exists due to a flaw
    related to search IDs, in which user input is not
    properly sanitized. A remote, authenticated attacker can
    exploit this, via a specially crafted URL, to read
    arbitrary files outside the restricted path.
    (CVE-2014-5197)

  - A cross-site scripting vulnerability exists due to the
    referrer header not being properly validated before
    returning it to users. A remote attacker can exploit
    this, via a specially crafted request, to execute script
    code in a user's browser session. (CVE-2014-5198)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAM9H");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk Enterprise 6.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];

install_url = build_url(qs:dir, port:port);

# Affected : 6.1.x < 6.1.3
if (ver =~ "^6\.1($|\.)" && ver_compare(ver:ver,fix:"6.1.3",strict:FALSE) < 0)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : 6.1.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
