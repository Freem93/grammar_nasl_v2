#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70100);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2011-2402", "CVE-2011-2403");
  script_bugtraq_id(48922, 48924);
  script_osvdb_id(74133, 74134);

  script_name(english:"HP Network Automation Multiple Vulnerabilities (HPSBMU02693)");
  script_summary(english:"Checks against reported version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote application has multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The HP Network Automation server is susceptible to XSS and SQL
injection attacks."
  );
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c02942385
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?118836b1");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 9.10.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_automation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("www/hp_network_automation");

port = get_http_port(default:443);
install = get_install_from_kb(appname:"hp_network_automation", port:port, exit_on_fail:TRUE);
ver = install['ver'];
url = build_url(qs:install['dir'], port:port);

if (
  ver == UNKNOWN_VER || 
  ver !~ "^[0-9]+(?:[0-9\.])+$"
) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'HP Network Automation', url);



# Check specific versions listed in advisory.
if (
  # 9.10 less than 9.10.01
  (
    ver_compare(ver:ver, fix:'9.10.01', strict:FALSE) == -1 &&
    ver_compare(ver:ver, fix:'9.10', strict:FALSE) != -1
  ) ||
  # Any 9.0
  (
    ver_compare(ver:ver, fix:'9.1', strict:FALSE) == -1 &&
    ver_compare(ver:ver, fix:'9.0', strict:FALSE) != -1
  ) ||
  # Any 7.5x or 7.6x
  (
    ver_compare(ver:ver, fix:'7.70', strict:FALSE) == -1 &&
    ver_compare(ver:ver, fix:'7.50', strict:FALSE) != -1
  ) ||
  # Any 7.2x
  (
    ver_compare(ver:ver, fix:'7.30', strict:FALSE) == -1 &&
    ver_compare(ver:ver, fix:'7.20', strict:FALSE) != -1
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + ver + 
             '\n  Fixed version     : 9.10.01' +
             '\n';
    security_warning(port: port, extra: report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Network Automation", url, ver);
