#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97858);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/23 13:29:51 $");

  script_cve_id("CVE-2017-1151");
  script_bugtraq_id(96841);
  script_osvdb_id(153594);

  script_name(english:"IBM WebSphere Application Server 8.0.0.10 < 8.0.0.14 / 8.5.5.3 < 8.5.5.12 / 9.0.0.0 < 9.0.0.4 OIDC Privilege Escalation");
  script_summary(english:"Reads the version number from the SOAP and GIOP services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 8.0.0.10 prior to 8.0.0.14, 8.5.5.3 prior to 8.5.5.12, or
9.0.0.0 prior to 9.0.0.4. It is, therefore, affected by a privilege
escalation vulnerability in the OpenID Connect (OIDC) Trust
Association Interceptor (TAI) that is triggered when the
com.ibm.websphere.security.InvokeTAIbeforeSSO custom property includes
the OIDC TAI class name com.ibm.ws.security.oidc.client.RelyingParty.
An unauthenticated, remote attacker can exploit this to gain elevated
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21999293");
  script_set_attribute(attribute:"solution", value:
"Apply IBM WebSphere Application Server version 8.0 Fix Pack 14 
(8.0.0.14) / 8.5 Fix Pack 12 (8.5.5.12) / 9.0 Fix Pack 4 (9.0.0.4) 
or later. Alternatively, upgrade to the minimal fix pack levels 
required by the interim fix and then apply Interim Fix PI74857. As a
workaround, disable InvokeTAIbeforeSSO for the OIDC TAI class per the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/21");

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

if (version =~ "^([89](\.0)?|8\.5)$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = "PI74857"; # Interim fix

if (version =~ "^9\.0\.")
{
  fix = '9.0.0.4';
  min = '9.0.0.0';
  pck = " (Fix Pack 4)";
}
else if (version =~ "^8\.5\.")
{
  fix = '8.5.5.12';
  min = '8.5.5.3';
  pck = " (Fix Pack 12)";
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.14';
  min = '8.0.0.10';
  pck = " (Fix Pack 14)";
}
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report =
  '\n  Version source    : ' + source  +
  '\n  Installed version : ' + version;

if (ver_compare(ver:version, minver:min, fix:fix, strict:FALSE) <  0)
    report +=
      '\n  Fixed version     : ' + fix + pck +
      '\n  Interim fix       : ' + itr;
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report += '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
