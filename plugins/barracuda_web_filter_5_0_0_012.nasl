#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85850);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_bugtraq_id(74033);
  script_osvdb_id(120514);
  script_xref(name:"EDB-ID", value:"36690");

  script_name(english:"Barracuda Web Filter <= 5.0.0.012 Remote Command Execution");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are affected by a
remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Barracuda Web Filter device is running a firmware version
at or prior to 5.0.0.012. It is, therefore, affected by a remote
command execution vulnerability in the web administration interface.
An authenticated, remote attacker can exploit this, via a specially
crafted request to index.cgi, to inject system commands as root.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported firmware version.");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/files/131366");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:barracuda:web_filter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("barracuda_web_filter_detect.nbin");
  script_require_keys("installed_sw/Barracuda Web Filter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app = "Barracuda Web Filter";

# Disallow branching of get_port
get_install_count(app_name:app, exit_if_zero:TRUE);
port     = get_http_port(default:8000, embedded:TRUE);
install  = get_single_install(app_name:app, port:port);
dir      = install['path'];
firmware = install["version"];

if (firmware == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app, port);

fix = "5.0.0.012";
if (ver_compare(ver:firmware, fix:fix, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n URL               : ' + build_url2(qs:dir, port:port) +
      '\n Installed version : ' + firmware +
      '\n Fixed version     : Contact vendor\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, firmware);
