#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92724);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/03 22:36:31 $");

  script_cve_id("CVE-2016-0359");
  script_bugtraq_id(91484);
  script_osvdb_id(140488);

  script_name(english:"IBM WebSphere Application Server 7.0 < 7.0.0.43 / 8.0 < 8.0.0.13 / 8.5 < 8.5.5.10 / Liberty 16.0 < 16.0.0.2 CRLF Sequences HTTP Response Splitting");
  script_summary(english:"Reads the version number from the SOAP and GIOP services or from HTTP responses.");

  script_set_attribute(attribute:"synopsis", value:
"A web application server running on the remote host is affected by an
HTTP response splitting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0 prior to 7.0.0.43, 8.0 prior to 8.0.0.13, 8.5 prior to
8.5.5.10, or 16.0 (Liberty) prior to 16.0.0.2. It is, therefore,
affected by an HTTP response splitting vulnerability due to a failure
to properly sanitize CRLF character sequences before user-supplied
input is included in HTTP responses. An unauthenticated, remote
attacker can exploit this, by convincing a user to visit a specially
crafted URL link, to inject arbitrary HTTP headers.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21982526");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 7.0 Fix Pack 43
(7.0.0.43) / 8.0 Fix Pack 13 (8.0.0.13) / 8.5 Fix Pack 10 (8.5.5.10)
Liberty 16.0 Fix Pack 2 (16.0.0.2) or later. Alternatively, apply the
appropriate interim fixes as recommended in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl", "websphere_liberty_detect.nbin");
  script_require_ports("Services/www", 8880, 8881, 9080, 9001, 9443);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:FALSE);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

app_name = "IBM WebSphere Application Server";

if (version =~ "^(([78]|16)((\.[0]+)?)|(8\.[5]))$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = FALSE; # 
paranoid_req = FALSE; # Reserved for versions with interim patches available

if (version =~ "^16\.0\.0\.")
{
  fix = '16.0.0.2';
  min = '16.0.0.0';
  itr = 'PI58918';
  pck = " (Fix Pack 2)";
}
else if (version =~ "^8\.5\.")
{
  if (version == "8.5.5.8" || version == "8.5.5.9") paranoid_req = TRUE;
  fix = '8.5.5.10';
  min = '8.5.0.0';
  itr = 'PI58918';
  pck = " (Fix Pack 10) for Full Profile / 16.0.0.2 (Fix Pack 2) for Liberty Profile";
}
else if (version =~ "^8\.0\.")
{
  if (version == "8.0.0.11" || version == "8.0.0.12") paranoid_req = TRUE;
  fix = '8.0.0.13';
  min = '8.0.0.0';
  itr = 'PI58918';
  pck = " (Fix Pack 13)";
}
else if (version =~ "^7\.0\.")
{
  if (version == "7.0.0.39" || version == "7.0.0.41") paranoid_req = TRUE;
  fix = '7.0.0.43';
  min = '7.0.0.0';
  itr = 'PI58918';
  pck = " (Fix Pack 43)";
}

# Interim fixes are available for specific versions
if (paranoid_req && report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, app_name, version, port);

if (fix && min &&
    ver_compare(ver:version, fix:fix, strict:FALSE) <  0 &&
    ver_compare(ver:version, fix:min, strict:FALSE) >= 0
)
{
  
  report =
    '\n  Version source    : ' + source  +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + pck +
    '\n  Interim fix       : ' + itr +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

