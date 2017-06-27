#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88965);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/03 17:07:25 $");

  script_cve_id("CVE-2014-7280");
  script_bugtraq_id(70274);
  script_osvdb_id(112728);
  script_xref(name:"EDB-ID", value:"34929");

  script_name(english:"Nessus Web UI Scanned Content Stored XSS");
  script_summary(english:"Checks the version of the web server.");

  script_set_attribute(attribute:"synopsis", value:
"A web server running on the remote host is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Nessus web server
running on the remote host is affected by a cross-site scripting
vulnerability in the web-based user interface (Web UI) due to improper
validation of input passed from plugins before returning it users. A
remote attacker can exploit this, via a specially crafted request, to
execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2014-08");
  script_set_attribute(attribute:"see_also", value:"https://www.thesecurityfactory.be/permalink/nessus-stored-xss.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade the plugin feed using 'nessus-update-plugins', restart the web
server, and verify Nessus Web UI version 2.3.4 (#85) or later is
running. The Web UI version can be viewed by logging in and clicking
the 'About' button.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2014/10/07");
  script_set_attribute(attribute:"patch_publication_date",value:"2014/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("nessus_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_require_keys("installed_sw/nessus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

get_install_count(app_name:"nessus", exit_if_zero:TRUE);

port = get_http_port(default:8834);

install = get_single_install(app_name:"nessus", port:port, exit_if_unknown_ver:TRUE);
path = install['path'];
install_loc = build_url(port:port, qs:path);

version = install['version'];

# Only 5.x is affected
if (version !~ "^5\.")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Nessus", install_loc, version);

# Only web UI 2.3.3 is affected
web_ui_version = install['Web UI Version'];
if (empty_or_null(web_ui_version)) web_ui_version = install['Nessus UI Version'];
if (empty_or_null(web_ui_version)) web_ui_version = UNKNOWN_VER;
if (web_ui_version =~ "^2.3.3($| )")
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n  Installed web UI version : ' + web_ui_version +
             '\n  Fixed web UI version     : 2.3.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Nessus", install_loc, version + " with web UI " + web_ui_version);
