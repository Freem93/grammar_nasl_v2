#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42262);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2014/05/24 02:15:09 $");

 script_cve_id("CVE-2009-0840", "CVE-2009-2281");
 script_bugtraq_id(36802);
 script_osvdb_id(56330, 59284);
 script_xref(name:"Secunia", value:"34520");

 script_name(english:"MapServer < 5.4.2 / 5.2.3 / 4.10.5 Buffer Overflow");
 script_summary(english:"Performs a banner check");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by
a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MapServer, an open source Internet map
server. The installed version reportedly contains an incomplete
fix for the vulnerability referenced by CVE-2009-0840. An attacker
may be able to exploit this issue to cause a denial of service
condition or execute arbitrary code on the remote system.");

 script_set_attribute(attribute:"see_also", value:"http://trac.osgeo.org/mapserver/ticket/2943");
 # http://trac.osgeo.org/mapserver/browser/tags/rel-4-10-5/mapserver/HISTORY.TXT
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f39007af");
 # http://trac.osgeo.org/mapserver/browser/tags/rel-5-2-3/mapserver/HISTORY.TXT
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a018ee0");
 # http://trac.osgeo.org/mapserver/browser/tags/rel-5-4-2/mapserver/HISTORY.TXT
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a966484");
 script_set_attribute(attribute:"solution", value:"Upgrade to MapServer 5.4.2 / 5.2.3 / 4.10.5.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/07/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/27");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

 script_dependencies("mapserver_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/mapserver", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "MapServer";
port = get_http_port(default:80);
install = get_install_from_kb(appname:'mapserver', port:port, exit_on_fail:TRUE);
version = install['ver'];
url = build_url(port:port, qs:install['dir']);

# Determine fixed version from branch.
if (version =~ "^[0-4]($|-|\.)") fix = "4.10.5";
else if (version =~ "^5($|-|\.[0-2]($|-|\.))") fix = "5.2.3";
else if (version =~ "^5\.[3-4]($|-|\.)") fix = "5.4.2";
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (ver_compare(app:'asterisk', ver:version, fix:fix) == -1 )
{
  if(report_verbosity > 0)
  {
    report =
      '\n  URL           : ' + url +
      '\n  Version       : ' + version +
      '\n  Fixed version : ' + fix +
      '\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
