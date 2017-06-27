#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100221);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/16 21:18:56 $");

  script_cve_id("CVE-2017-1137");
  script_osvdb_id(157081);

  script_name(english:"IBM WebSphere Application Server 8.0 < 8.0.0.14 / 8.5 < 8.5.5.12 Administrative Console Information Disclosure");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"A web application server running on the remote host is affected by an
information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Application Server running on the remote
host is 8.0 prior to 8.0.0.14 or 8.5 prior to 8.5.5.12. It is,
therefore, affected by an unspecified flaw in the administrative
console due to weaker than expected security. An unauthenticated,
remote attacker can exploit this to disclose sensitive information or
to gain unauthorized access to the administrative console.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998469");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 8.0 Fix Pack 14 
(8.0.0.14) / 8.5 Fix Pack 12 (8.5.5.12) or later. Note that the Fix
Packs are scheduled for release in Q3 or Q4 2017; however, IBM has
released Interim Fix PI76088 to address this vulnerability until the
Fix Packs are released.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

if (version =~ "^8((\.5(\.[05])?)?|(\.0(\.0)?)?)$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = FALSE; # 
if (version =~ "^8\.5\.")
{
  fix = '8.5.5.12';
  min = '8.5.0.0';
  itr = 'PI76088';
  pck = " (Fix Pack 12)";
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.14';
  min = '8.0.0.0';
  itr = 'PI76088';
  pck = " (Fix Pack 14)";
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
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

