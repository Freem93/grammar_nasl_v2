#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89785);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/30 14:31:29 $");

  script_cve_id("CVE-2016-1288");
  script_bugtraq_id(83936);
  script_osvdb_id(135230);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu24840");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160302-wsa");

  script_name(english:"Cisco Web Security Appliance HTTPS Packet Processing DoS (cisco-sa-20160302-wsa)");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Web Security
Appliance (WSA) is affected by a denial of service vulnerability in
the web proxy framework due to improper processing of HTTPS packets.
An unauthenticated, remote attacker can exploit this vulnerability,
via a malformed HTTPS request packet, to cause all requests traversing
the WSA to be dropped, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-wsa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c99dc6df");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu24840.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_wsa_version.nasl");

  script_require_keys("Settings/ParanoidReport","Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');

# Device has to have HTTPS proxying enabled
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

display_fix = FALSE;

if (ver_compare(ver:ver, fix:"8.5.3.051", strict:FALSE) < 0)
  display_fix = "8.5.3-051";
else if (ver =~ "^9\.0\." && ver_compare(ver:ver, fix:"9.0.0.485", strict:FALSE) < 0)
  display_fix = "9.0.0-485";

if (!display_fix)
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

report =
  '\n  Installed version : ' + display_ver +
  '\n  Fixed version     : ' + display_fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
