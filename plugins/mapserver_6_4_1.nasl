#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72094);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2013-7262");
  script_bugtraq_id(64671);
  script_osvdb_id(101736);

  script_name(english:"MapServer < 5.6.9 / 6.0.4 / 6.2.2 / 6.4.1 SQL Injection");
  script_summary(english:"Checks MapServer version.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a version of MapServer that may be affected
by a SQL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MapServer hosted on the remote web server may be
affected by a SQL injection vulnerability due to a failure to properly
sanitize user-supplied input.  Specifically, the
mPostGISLayerSetTimeFilter function in mappostgis.c does not properly
sanitize user-supplied input passed via PostGIS TIME filters, leading to
a possible unintended disclosure of data. 

Note: In order for this vulnerability to be exploited, WMS-Time must be
configured and PostGIS must be in use."
  );
  # http://www.mapserver.org/development/changelog/changelog-6-4.html#changelog-6-4-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aae4752e");
  script_set_attribute(attribute:"see_also", value:"https://github.com/mapserver/mapserver/issues/4834");
  # https://github.com/mapserver/mapserver/commit/3a10f6b829297dae63492a8c63385044bc6953ed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c82eb5b");
  script_set_attribute(attribute:"solution", value:"Upgrade to MapServer 5.6.9 / 6.0.4 / 6.2.2 / 6.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:umn:mapserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("mapserver_detect.nasl");
  script_require_keys("www/mapserver", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app_name = "MapServer";

port = get_http_port(default:80);

installed_mapserver = get_install_from_kb(appname:'mapserver', port:port, exit_on_fail:TRUE);

mapserver_ver = installed_mapserver['ver'];
mapserver_url = build_url(port:port, qs:installed_mapserver['dir']);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version_fixed = make_array(
  '56', '5.6.9',
  '60', '6.0.4',
  '62', '6.2.2',
  '64', '6.4.1',
  '*', '6.4.1'
);

# Get the discovered version branch to determine which version compare
# to run. To do this, just concatenate the major version and first
# minor version.
version_branch = split(mapserver_ver, sep:'.', keep:FALSE);
version_branch = version_branch[0] + version_branch[1];

# Make sure the branch is one of the currently developed branches,
# otherwise go to default.
if (int(version_branch) < 56 || int(version_branch) > 64)
{
  version_branch = '*';
}

# Development branches are odd-numbered and correspond to the next
# highest even numbered release branch.
if (int(version_branch) % 2 == 1)
{
  version_branch = string(int(version_branch) + 1);
}

# Make sure we have a valid version_branch or default to wildcard.
if (isnull(version_fixed[version_branch]))
{
  version_branch = '*';
}

version_check = ver_compare(app:'asterisk', ver:mapserver_ver, fix:version_fixed[version_branch]);

# Determine whether the discovered version is vulnerable.
if (version_check == -1)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  URL               : '+mapserver_url+
    '\n  Installed version : '+mapserver_ver+
    '\n  Fixed version     : '+version_fixed[version_branch]+'\n';
    security_warning(port:port,extra:report);
  }
  else  security_warning(port);

  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  exit(0);
}
else if (isnull(version_check)) audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name, mapserver_url);
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, mapserver_url, mapserver_ver);
