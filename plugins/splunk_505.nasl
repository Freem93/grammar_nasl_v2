#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70213);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/06/23 19:48:37 $");

  script_cve_id("CVE-2013-6771", "CVE-2013-7394");
  script_bugtraq_id(62632, 69169);
  script_osvdb_id(97720, 105734);

  script_name(english:"Splunk < 5.0.5 Multiple Code Execution Vulnerabilities");
  script_summary(english:"Checks the version of Splunk.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an application that is affected by
multiple code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the Splunk Web hosted on the remote
web server is affected by multiple code execution vulnerabilities :

  - A directory traversal vulnerability exists in the
    collect script. A remote attacker can exploit this,
    using the 'file' parameter, to execute arbitrary
    commands. (CVE-2013-6771)

  - A flaw exists in the 'echo.sh' script that allows a
    remote, authenticated attacker to execute arbitrary
    commands on the underlying operating system by using a
    specially crafted string. (CVE-2013-7394)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-052/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-053/");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAH76");
  script_set_attribute(attribute:"see_also", value:"http://docs.splunk.com/Documentation/Splunk/latest/ReleaseNotes/5.0.5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk 5.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

if (ver_compare(ver:ver,fix:"5.0.5",strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : 5.0.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
