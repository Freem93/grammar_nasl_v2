#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34507);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2008-6816");
  script_bugtraq_id(31933);
  script_osvdb_id(50051);
  script_xref(name:"Secunia", value:"32456");

  script_name(english:"Eaton Network Shutdown Module < 3.20 Authentication Bypass / Command Execution");
  script_summary(english:"Checks version or tests an action");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
several issues.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Network Shutdown Module install on
the remote host is earlier than 3.20.  It therefore reportedly fails to
require authentication before allowing a remote attacker to add custom
actions through the 'pane_actionbutton.php' script and then execute them
via the 'exec_action.php' script.

Note that the application runs by default with Administrator privileges
under Windows so successful exploitation of this issue could result in a
complete compromise of the affected system.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Oct/204");
  # http://web.archive.org/web/20101203023356/http://download.mgeops.com/install/win32/nsm/release_note_nsm_320.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9e0eb5a");
  script_set_attribute(attribute:"solution", value:"Upgrade to Network Shutdown Module version 3.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:eaton:network_shutdown_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("network_shutdown_module_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/eaton_nsm");
  script_require_ports("Services/www", 4679);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:4679, embedded:FALSE);


install = get_install_from_kb(appname:"eaton_nsm", port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(qs:dir, port:port);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Eaton Network Shutdown Module", install_url);

if (version =~ "^([0-2]\.|3\.([0-9]|[01][0-9])[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.20' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Eaton Network Shutdown Module', install_url);
