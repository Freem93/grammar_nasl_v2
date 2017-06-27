#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79724);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id(
    "CVE-2014-3511",
    "CVE-2014-8301",
    "CVE-2014-8302",
    "CVE-2014-8303"
  );
  script_bugtraq_id(
    69079
  );
  script_osvdb_id(
    109896,
    112489,
    112490,
    112491
  );

  script_name(english:"Splunk Enterprise 5.0.x < 5.0.10 / 6.1.x < 6.1.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Splunk Enterprise hosted on the
remote web server is 5.0.x prior to 5.0.10 or 6.1.x prior to 6.1.4. It
is, therefore, affected by the following vulnerabilities :

  - The included OpenSSL library contains a TLS downgrade
    weakness. By using fragmented ClientHello messages, a
    remote man-in-the-middle attacker can force downgrading
    to TLS 1.0. (CVE-2014-3511)

  - A cross-site scripting flaw exists due to improper
    validation of user-supplied input to the HTTP referrer
    header. A remote attacker can exploit this, using a
    specially crafted request, to execute arbitrary script
    code in the user's browser session within the trust
    relationship. Note that this only affects the 5.0.x
    branch. (CVE-2014-8301)

  - A cross-site scripting vulnerability exists within the
    Dashboard due to improper validation of user-supplied
    input. A remote attacker can exploit this, using a
    specially crafted request, to execute arbitrary script
    code in the user's browser session within the trust
    relationship. (CVE-2014-8302)

  - A cross-site scripting vulnerabilities exists due to
    improper validation of user-supplied input when parsing
    events. This allows a remote attacker, using a specially
    crafted request, to execute arbitrary script code in the
    user's browser session within the trust relationship.
    (CVE-2014-8303)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAANHS");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk Enterprise 6.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

# Affected : 5.0.x < 5.0.10
# Affected : 6.1.x < 6.1.4
if (ver =~ "^5\.0($|[^0-9])") fix = '5.0.10';
else if (ver =~ "^6\.1($|[^0-9])") fix = '6.1.3';

if (fix && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : ' +fix+'\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
