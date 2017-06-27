#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86058);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/23 14:26:24 $");

  script_cve_id("CVE-2015-5440");
  script_osvdb_id(127308);
  script_xref(name:"HP", value:"SSRT101565");
  script_xref(name:"HP", value:"HPSBGN03504");
  script_xref(name:"HP", value:"emr_na-c04790231");

  script_name(english:"HP Universal Configuration Management Database Server (UCMDB) Local Information Disclosure (HPSBGN03504)");
  script_summary(english:"Checks the UCMDB Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a local information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Universal Configuration Management Database Server
(UCMDB) running on the remote web server is affected by an unspecified
local information disclosure vulnerability. A local attacker can
exploit this to gain access to admin or root password information.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04790231
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08712565");
  # https://packetstormsecurity.com/files/133518/HP-Security-Bulletin-HPSBGN03504-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51652e1e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Universal Configuration Management Database Server
(UCMDB) version 10.01 CUP12 / 10.11 CUP6 / 10.21.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:universal_configuration_management_database");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("hp_ucmdb_server_detect.nbin");
  script_require_keys("installed_sw/HP Universal Configuration Management Database Server");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "HP Universal Configuration Management Database Server";
get_install_count(app_name:app_name, exit_if_zero:TRUE);
port = get_http_port(default:8080);

ins = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
url = build_url(port:port, qs:ins['url']);
ver = ins['version'];
fix = FALSE;

# Only versions of 10 known to have the problem
if(ver !~ "^10[^0-9]")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, ver);

# CUP version number is unknown in these cases
if(ver =~ "^10\.(01|11)[^0-9]*$" && report_paranoia < 2)
  audit(AUDIT_VER_NOT_GRANULAR, app_name, ver);

if(ver =~ "^10\.(01|00)[^0-9]*$")
  fix = "10.01 CUP12";
else if(ver =~ "^10\.(10|11)[^0-9]*$")
  fix = "10.11 CUP6";
else if(ver =~ "^10\.20[^0-9]*$")
  fix = "10.21";

if(!fix)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, ver);

if(report_verbosity > 0) {
  report =
    '\n URL               : '+url+
    '\n Installed version : '+ver+
    '\n Fixed version     : '+fix+
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
