#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71784);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/23 19:48:37 $");

  script_cve_id("CVE-2013-7337");
  script_bugtraq_id(64419);
  script_osvdb_id(101149);

  script_name(english:"Splunk Enterprise 6.x < 6.0.1 Malformed Packet DoS");
  script_summary(english:"Checks the version of Splunk.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an application that may be affected by
a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the Splunk Enterprise hosted on the
remote web server may be affected by a denial of service vulnerability
that is triggered by malformed network input, resulting in the Splunk
server becoming unavailable.

Note that this only affects Splunk Enterprise 6.0 components 
configured as data 'receivers' on the listening or receiving port(s),
and it impacts Splunk Enterprise instances configured as indexers as
well as any forwarders configured as intermediate forwarders.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAJD5");
  script_set_attribute(attribute:"see_also", value:"http://docs.splunk.com/Documentation/Splunk/6.0.1/ReleaseNotes/6.0.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk Enterprise 6.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

license = install['License'];
if (isnull(license) || license != "Enterprise")
  exit(0, "The Splunk install at "+install_url+" is not the Enterprise variant.");

if (ver =~ "^6\." && ver_compare(ver:ver,fix:"6.0.1",strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : 6.0.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
