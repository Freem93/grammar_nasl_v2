#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72345);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2013-6955");
  script_bugtraq_id(64516);
  script_osvdb_id(101247);
  script_xref(name:"EDB-ID", value:"30470");
  script_xref(name:"CERT", value:"615910");

  script_name(english:"Synology DiskStation Manager 4.3-x < 4.3-3810 Update 1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Synology DiskStation Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote Synology DiskStation Manager is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Synology DiskStation Manager
installed on the remote host is 4.3-x equal or prior to 4.3-3810. It
is, therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in the File
    Station component due to improper validation in the
    'imageSelector.cgi' script of values submitted in the
    X-TMP-FILE header field along with the X-TYPE-NAME:
    SLICEUPLOAD header field to the 'imageSelector.cgi'
    script. (CVE-2013-6955)

  - An issue exists in the Auto Block feature that could
    allow IP addresses to be improperly added to the Block
    List.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531602/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.3-3810 Update 1 or later or contact the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Synology DiskStation Manager SLICEUPLOAD Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:synology:diskstation_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
  (ver[0] == 4 && ver[1] == 3 && ver[2] < 3810) ||
  ((ver[0] == 4 && ver[1] == 3 && ver[2] == 3810) && report_paranoia == 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.3-3810 Update 1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
