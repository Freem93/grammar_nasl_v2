#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86804);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");
  
  script_cve_id("CVE-2015-2169", "CVE-2015-5061");
  script_bugtraq_id(75389, 75411);
  script_osvdb_id(123539, 123630);
  script_xref(name:"EDB-ID", value:"37395");

  script_name(english:"ManageEngine AssetExplorer < 6.1.0 Build 6113 Multiple XSS");
  script_summary(english:"Checks the version of ManageEngine AssetExplorer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine AssetExplorer running on the remote host
is prior to 6.1.0 build 6113. It is, therefore, affected by multiple
cross-site scripting (XSS) vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper validation of input to the Publisher name
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in the user's
    browser session. (CVE-2015-2169)

  - A cross-site scripting vulnerability exists in the
    VendorDef.do script due to improper validation of input
    to the 'organizationName' POST parameter before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in the user's
    browser session. (CVE-2015-5061)");
  # http://www.manageengine.com/products/asset-explorer/sp-readme.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b97aaa3");
  script_set_attribute(attribute:"solution", value:
"Upgrade ManageEngine AssetExplorer to version 6.1.0 build 6113 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoho:manageengine_assetexplorer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_assetexplorer_detect.nasl");
  script_require_keys("installed_sw/ManageEngine AssetExplorer");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "ManageEngine AssetExplorer";
get_install_count(app_name : appname, exit_if_zero : TRUE);
port = get_http_port(default:8080);

install = get_single_install(
  app_name : appname,
  port:port, 
  exit_if_unknown_ver:TRUE
);
dir = install['path'];
install_url = build_url(port:port, qs:dir);

version = install['version'];
ver = split(version, sep:" Build ", keep:FALSE);
full_ver = ver[0] + '.' + ver[1];

if (ver_compare(ver:full_ver, fix:'6.1.0.6113', strict:FALSE) == -1) 
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if(report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0 Build 6113' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
} 
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
