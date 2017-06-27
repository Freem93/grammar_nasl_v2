#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83036);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-7886");
  script_bugtraq_id(74175);
  script_osvdb_id(
    120900,
    120901,
    120902,
    120903
  );
  script_xref(name:"CERT", value:"750060");
  script_xref(name:"HP", value:"emr_na-c04574207");
  script_xref(name:"HP", value:"HPSBMU03264");
  script_xref(name:"HP", value:"SSRT101865");

  script_name(english:"HP Network Automation Multiple Remote Vulnerabilities (HPSBMU03264)");
  script_summary(english:"Checks the reported version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Network Automation running on the remote host is
affected by multiple vulnerabilities in the administrative web 
interface. These vulnerabilities include multiple cross-site request
forgeries, cross-site scripting, and clickjacking vulnerabilities.
An unauthenticated, remote attacker can exploit these vulnerabilities
to escalate privileges, disclose sensitive information, execute
arbitrary script code, or to cause a denial of service condition.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04574207
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03d90e8e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Network Automation version 9.22.02 / 10.00.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_automation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_na_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/hp_network_automation");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "HP Network Automation";

get_kb_item_or_exit("www/hp_network_automation");

port = get_http_port(default:443);
install = get_install_from_kb(appname:"hp_network_automation", port:port, exit_on_fail:TRUE);
ver = install['ver'];
url = build_url(qs:install['dir'], port:port);

if (
  ver == UNKNOWN_VER ||
  ver !~ "^[0-9]+(?:[0-9\.])+$"
) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, url);

# Advisory lists the following as vulnerable :
#   - HP Network Automation v9.0X
#   - HP Network Automation v9.1X
#   - HP Network Automation v9.2X
#   - HP Network Automation v10.X
# Check for these versions up to the available fixes
if (ver =~ "^9\.")  fix = '9.22.02';
if (ver =~ "^10\.") fix = '10.00.01';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + ver +
             '\n  Fixed version     : ' + fix +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
