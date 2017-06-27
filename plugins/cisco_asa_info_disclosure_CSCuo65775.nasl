#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91963);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/08 14:36:26 $");

  script_cve_id("CVE-2016-1295");
  script_osvdb_id(133009);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo65775");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160115-asa");

  script_name(english:"Cisco ASA AnyConnect Client Authentication Attempt Handling Information Disclosure (cisco-sa-20160115-asa)");
  script_summary(english:"Attempts to get the device version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Adaptive
Security Appliance (ASA) software running on the remote device is
affected by an information disclosure vulnerability due to a failure
to protect sensitive data during a Cisco AnyConnect client
authentication attempt. An unauthenticated, remote attacker can
exploit this, by attempting to authenticate to the Cisco ASA with
AnyConnect, to disclose sensitive data, including the ASA software
version.

Note that the SSL VPN feature must be enabled for the device to be
affected by this vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160115-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?408d7839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuo65775.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_asa_ssl_vpn_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("Services/cisco-ssl-vpn-svr");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Cisco ASA";
port    = get_service(svc:"cisco-ssl-vpn-svr", default:443, exit_on_fail:TRUE);
url = '/';
header = {"X-Aggregate-Auth":1};
version = UNKNOWN_VER;

res = http_send_recv3(method:"POST", item: url, port:port, add_headers: header, data: "nessus", exit_on_fail:TRUE);

if (res[0] =~ "^HTTP/[0-9.]+ +200" && "<config-auth client=" >< res[2])
{
  # Example: <version who="sg">9.1(5)</version>
  pat = "<version [^>]+>([0-9.]+\([0-9.]+\)\d{0,2})</version>";

  matches = eregmatch(pattern:pat, string:res[2]);
  if (!isnull(matches))
  {
    version = matches[1]; 

    report = 
      '\n' + "Nessus was able to determine the remote Cisco ASA version :" +
      '\n' +
      '\n' + "  URL     : " + build_url(port:port, qs:url) + 
      '\n' + "  Version : " + version +
      '\n';
    security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  }
  else audit(AUDIT_DEVICE_NOT_VULN, "The "+appname+" on port "+port);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The "+appname+" on port "+port);
