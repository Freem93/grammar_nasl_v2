#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67172);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/16 14:42:20 $");

  script_bugtraq_id(48934);
  script_osvdb_id(74154, 74155);
  script_xref(name:"IAVB", value:"2011-B-0089");

  script_name(english:"Sybase EAServer 6.x < 6.3.1 ESD#3 Multiple Code Execution Vulnerabilities");
  script_summary(english:"Checks version of EAServer");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sybase EAServer installed on the remote host is 6.x
prior to 6.3.1 ESD#3.  It is, therefore, potentially affected by
multiple code execution vulnerabilities in the handling of login
packets.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-245/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-246/");
  script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/detail?id=1094235");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sybase EAServer 6.3.1 ESD#3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

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
include("http.inc");
include("webapp_func.inc");

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

if (version =~ '^6\\.' && ver_compare(ver:version, fix:'6.3.1.07', strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : 6.3.1.07 Build 63107\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Sybase EAServer', url, version + ' Build ' + build);
