#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72343);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_bugtraq_id(62310);
  script_osvdb_id(97169, 97170);
  script_xref(name:"EDB-ID", value:"28243");

  script_name(english:"Synology DiskStation Manager < 4.3-3776 Update 2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Synology DiskStation Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote Synology DiskStation Manager is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Synology DiskStation Manager
installed on the remote host is a version prior to 4.3-3776 Update 2. 
It is, therefore, potentially affected by the following 
vulnerabilities :

  - An input validation error exists in the
    'externaldevices.cgi' script that allows any
    administrative user to execute arbitrary commands with
    root privileges on the remote host.

  - An input validation error exists in the 'wallpaper.cgi'
    script that allows any authenticated user to download
    arbitrary files.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Sep/53");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.3-3776 Update 2 or later, or contact the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:synology:diskstation_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("synology_diskstation_manager_detect.nbin");
  script_require_keys("www/synology_dsm");
  script_require_ports("Services/www", 5000, 5001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:5000, embedded:TRUE);

install = get_install_from_kb(appname:"synology_dsm", port:port, exit_on_fail:TRUE);

app = "Synology DiskStation Manager (DSM)";
dir = install["dir"];
install_loc = build_url(port:port, qs:dir + "/");

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 4) ||
  (ver[0] == 4 && ver[1] < 3) ||
  (ver[0] == 4 && ver[1] == 3 && ver[2] < 3776) ||
  ((ver[0] == 4 && ver[1] == 3 && ver[2] == 3776) && report_paranoia == 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.3-3776 Update 2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
