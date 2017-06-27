#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97019);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 14:51:05 $");

  script_osvdb_id(150713);

  script_name(english:"IBM DataPower Gateway < 7.5.2.2 Default Admin Password Security Bypass");
  script_summary(english:"Checks the version of the IBM DataPower Gateway.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM DataPower Gateway 
running on the remote host is prior to 7.5.2.2. It is, therefore,
affected by a security bypass vulnerability due to the default
password still being accepted as valid if the administrator logs in
before the startup configuration is completed.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT18055");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM DataPower Gateway version 7.5.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:datapower_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_datapower_gateway_detect.nbin");
  script_require_keys("installed_sw/IBM DataPower Gateway");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9090);
appname = "IBM DataPower Gateway";

install = get_install_from_kb(appname: appname, port: port, exit_on_fail: TRUE);
dir = install["dir"];
url = build_url(port:port, qs:dir);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

ver = split(version, sep:".", keep:FALSE);

if(ver[0] == '7' && max_index(ver) < 4) 
  audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);

fix = '7.5.2.2';
if (ver_compare(ver: version, fix: fix, strict: FALSE) < 0)
{
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else 
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
}
