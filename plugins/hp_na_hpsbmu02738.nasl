#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70101);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2011-4790");
  script_bugtraq_id(51746);
  script_osvdb_id(78672);

  script_name(english:"HP Network Automation Remote Unauthorized Access (HPSBMU02738)");
  script_summary(english:"Checks reported version");

  script_set_attribute(attribute:"synopsis", value:
"The remote application has a remote unauthorized access
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP Network Automation server has a remote unauthorized access
vulnerability.");
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03171149
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc6948b8");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 9.10.02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_automation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

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
  # 9.10 less than 9.10.02
  (
    ver_compare(ver:ver, fix:'9.10.02', strict:FALSE) == -1 &&
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
  )
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + ver + 
             '\n  Fixed version     : 9.10.02' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Network Automation", url, ver);
