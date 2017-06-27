#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94512);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/27 16:20:34 $");

  script_cve_id("CVE-2016-5983", "CVE-2016-5986");
  script_bugtraq_id(93013, 93162);
  script_osvdb_id(144709, 144340);

  script_name(english:"IBM WebSphere Application Server 7.0 < 7.0.0.43 / 8.0 < 8.0.0.13 / 8.5 < 8.5.5.11 / 9.0 < 9.0.0.2 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0 prior to 7.0.0.43, 8.0 prior to 8.0.0.13, 8.5 prior to
8.5.5.11, or 9.0 prior to 9.0.0.2. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists due to
    improper sanitization user-supplied input when
    deserializing Java objects. An authenticated, remote
    attacker can exploit this, via a crafted serialized
    object, to execute arbitrary Java code. (CVE-2016-5983)

  - An information disclosure vulnerability exists due to
    improper handling of responses. An unauthenticated,
    remote attacker can exploit this to disclose sensitive
    server identification information. (CVE-2016-5986)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21990056");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21990060");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 7.0 Fix Pack 43
(7.0.0.43) / 8.0 Fix Pack 13 (8.0.0.13) / 8.5 Fix Pack 11 (8.5.5.11) /
9.0 Fix Pack 2 (9.0.0.2) or later. Alternatively, apply Interim Fixes
PI67093 and PI70737.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");

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

if (version =~ "^([78]+((\.[0]+)?)|(8\.[5])|(9\.[0]))$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = FALSE; #

if (version =~ "^9\.0\.")
{
  fix = '9.0.0.2';
  min = '9.0.0.0';
  itr = 'PI67093, PI70737';
  pck = " (Fix Pack 2)";
}

else if (version =~ "^8\.5\.")
{
  fix = '8.5.5.11';
  min = '8.5.0.0';
  itr = 'PI67093, PI70737';
  pck = " (Fix Pack 11)";
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.13';
  min = '8.0.0.0';
  itr = 'PI67093, PI70737';
  pck = " (Fix Pack 13)";
}
else if (version =~ "^7\.0\.")
{
  fix = '7.0.0.43';
  min = '7.0.0.0';
  itr = 'PI67093, PI70737';
  pck = " (Fix Pack 43)";
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
