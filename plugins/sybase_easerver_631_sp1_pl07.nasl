#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67007);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:20 $");

  script_bugtraq_id(60614, 61358);
  script_osvdb_id(94397, 94398, 94399, 95469, 95470);
  script_xref(name:"EDB-ID", value:"27011");
  script_xref(name:"IAVA", value:"2013-A-0123");

  script_name(english:"Sybase EAServer 6.3.1 < 6.3.1.07 Build 63107 / 6.2 < 6.2.0.12 Build 62012 Multiple Vulnerabilities");
  script_summary(english:"Checks version of EAServer");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sybase EAServer installed on the remote host is 6.3.1
earlier than 6.3.1.07 Build 63107 or 6.2 earlier than 6.2.0.12 Build
62012.  As such, it is potentially affected by multiple 
vulnerabilities :

  - An unspecified error can be exploited to access
    otherwise inaccessible, deployed applications.

  - An unspecified error can be exploited to disclose
    the contents of arbitrary directories and files.

  - An unspecified error within the WSH service can be
    exploited to disclose certain credentials from
    unspecified configuration files and execute arbitrary
    OS commands.

Note that the second and third issues only affect version 6.3.1 of
EAServer.");
  script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/detail?id=1099353");
  script_set_attribute(attribute:"see_also", value:"http://forums.cnet.com/7726-6132_102-5468915.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sybase EAServer 6.2.0.12 Build 62012 / 6.3.1.07 Build 63107
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sybase:easerver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sybase_easerver_detect.nasl");
  script_require_keys("www/sybase_easerver");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

get_kb_item_or_exit("www/sybase_easerver");

port = get_http_port(default:8000);
install = get_install_from_kb(appname:'sybase_easerver', port:port, exit_on_fail:TRUE);

dir = install['dir'];
version = install['ver'];

url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Sybase EAServer', url);

fix = '';
matches = eregmatch(pattern:'^([0-9\\.]+) Build ([0-9\\.]+)', string:version);
if (isnull(matches)) exit(1, 'Failed to parse the version number.');

version = matches[1];
build = matches[2];

if (version =~ '^6\\.2(\\.|$)')
{
  if (ver_compare(ver:version, fix:'6.2.0.12', strict:FALSE) < 0) fix = '6.2.0.12 Build 62012';
  else if (ver_compare(ver:version, fix:'6.2.0.12', strict:FALSE) == 0)
  {
    parts = split(build, sep:'.', keep:FALSE);
    if (int(parts[0]) < 62012)
      fix = '6.2.0.12 Build 62012';
  }
}
else if (version =~ '^6\\.3\\.1(\\.|$)')
{
  if (ver_compare(ver:version, fix:'6.3.1.07', strict:FALSE) < 0) fix = '6.3.1.07 Build 63107.19926';
  else if (ver_compare(ver:version, fix:'6.3.1.07', strict:FALSE) == 0)
  {
    parts = split(build, sep:'.', keep:FALSE);
    if (int(parts[0]) < 63107)
      fix = '6.3.1.07 Build 63107.19926';
    else if (int(parts[0]) == 63107)
    {
      if (
        (max_index(parts) < 2) ||
        (max_index(parts) == 2 && int(parts[1]) < 19926))
        fix = '6.3.1.07 Build 63107.19926';
    }
  }
}

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Sybase EAServer', url, version + ' Build ' + build);
