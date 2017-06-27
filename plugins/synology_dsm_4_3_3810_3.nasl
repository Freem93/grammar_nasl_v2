#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72346);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2013-6987");
  script_bugtraq_id(64483);
  script_osvdb_id(
    101262,
    101263,
    101264,
    101265,
    101266,
    101267,
    101268
  );
  script_name(english:"Synology DiskStation Manager < 4.3-3810 Update 3 Multiple FileBrowser Component Directory Traversal Vulnerabilities");
  script_summary(english:"Checks the version of Synology DiskStation Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote Synology DiskStation Manager is affected by multiple
directory traversal vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Synology DiskStation Manager
installed on the remote host is 4.3-x equal or prior to 4.3-3810.  It
is, therefore, affected by multiple directory traversal vulnerabilities
in the FileBrowser component.  The issue exists due to improper
validation of values submitted to the various file parameters in the
following scripts in the '/webapi/FileStation' directory :

  - html5_upload.cgi
  - file_delete.cgi
  - file_download.cgi
  - file_sharing.cgi
  - file_share.cgi
  - file_MVCP.cgi
  - file_rename.cgi

Any authenticated user can exploit these affected files to read, write,
and delete arbitrary files. 

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.3-3810 Update 3 or later, or contact the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
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
  (ver[0] == 4 && ver[1] == 3 && ver[2] < 3810) ||
  ((ver[0] == 4 && ver[1] == 3 && ver[2] == 3810) && report_paranoia == 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_loc +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.3-3810 Update 3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
