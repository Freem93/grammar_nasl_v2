#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90316);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/02 15:47:18 $");

  script_cve_id("CVE-2015-7417");
  script_bugtraq_id(81738);
  script_osvdb_id(133484);

  script_name(english:"IBM WebSphere Application Server 7.0 < 7.0.0.41 / 8.0 < 8.0.0.12 / 8.5 < 8.5.5.9 OAuth Provider XSS");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0 prior to 7.0.0.41, 8.0 prior to 8.0.0.12, or 8.5 prior to
8.5.5.9. It is, therefore, potentially affected by a reflected
cross-site scripting (XSS) vulnerability due to a failure to properly
validate output from the OAuth provider before returning it to users.
An authenticated, remote attacker can exploit this, via a specially
crafted URL, to execute arbitrary script code in a user's browser
session within the security context of the hosting website.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21974520");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 7.0 Fix Pack 41
(7.0.0.41) / 8.0 Fix Pack 12 (8.0.0.12) / 8.5 Fix Pack 9 (8.5.5.9) or
later. Alternatively, apply the appropriate Interim Fixes as
recommended in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (version =~ "^([78]+((\.[0]+)?)|(8\.[5]))$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = FALSE; # 
if (version =~ "^8\.5\.")
{
  fix = '8.5.5.9';
  min = '8.5.0.0';
  itr = 'PI49272';
  pck = " (Fix Pack 9)";
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.12';
  min = '8.0.0.0';
  itr = 'PI49272';
  pck = " (Fix Pack 12)";
}
else if (version =~ "^7\.0\.")
{
  fix = '7.0.0.41';
  min = '7.0.0.0';
  itr = 'PI49272';
  pck = " (Fix Pack 41)";
}

if (fix && min &&
    ver_compare(ver:version, fix:fix, strict:FALSE) <  0 &&
    ver_compare(ver:version, fix:min, strict:FALSE) >= 0
)
{
  report =
    '\n  Version source    : ' + source  +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + pck +
    '\n  Interim fixes     : ' + itr +
    '\n';
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report, xss:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

