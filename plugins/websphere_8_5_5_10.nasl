#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96178);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/03 14:55:09 $");

  script_cve_id("CVE-2016-0377");
  script_bugtraq_id(92514);
  script_osvdb_id(143034);

  script_name(english:"IBM WebSphere Application Server 7.0 < 7.0.0.43 / 8.0 < 8.0.0.13 / 8.5 < 8.5.5.10 Information Disclosure");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the IBM WebSphere Application Server running on the
remote host is 7.0 prior to 7.0.0.43, 8.0 prior to 8.0.0.13, or 8.5
prior to 8.5.5.10. It is, therefore, affected by an information
disclosure vulnerability in the Administrative Console due to
improperly setting the CSRFtoken cookie. An authenticated, remote
attacker can exploit this to disclose sensitive information.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21980645");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 7.0 Fix Pack 43
(7.0.0.43) / 8.0 Fix Pack 13 (8.0.0.13) / 8.5 Fix Pack 10 (8.5.5.10) or 
later. Alternatively, apply the appropriate Interim Fixes as
recommended in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881, 9001);
  script_require_keys("www/WebSphere", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8880, embedded:FALSE);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

app_name = "IBM WebSphere Application Server";

if (version =~ "^(([78])((\.[0]+)?)|(8\.[5]))$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = 'PI56917'; # Interim fix (same for all versions for this vuln)

if (version =~ "^8\.5\.")
{
  fix = '8.5.5.10';
  min = '8.5.0.0';
  pck = " (Fix Pack 10)";
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.13';
  min = '8.0.0.0';
  pck = " (Fix Pack 13)";
}
else if (version =~ "^7\.0\.")
{
  fix = '7.0.0.43';
  min = '7.0.0.0';
  pck = " (Fix Pack 43)";
}

if (fix && min && ver_compare(ver:version, fix:fix, minver:min, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + source  +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + pck +
    '\n  Interim fixes     : ' + itr +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
