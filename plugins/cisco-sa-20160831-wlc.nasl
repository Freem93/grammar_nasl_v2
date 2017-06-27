#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94108);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/24 19:17:53 $");

  script_cve_id(
    "CVE-2016-6375",
    "CVE-2016-6376"
  );
  script_bugtraq_id(
    92712,
    92716
  );
  script_osvdb_id(
    143638,
    143639
  );
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160831-wlc-1");
  script_xref(name:"IAVA", value:"2016-A-0275");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160831-wlc-2");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz40221");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz40263");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Wireless LAN
Controller (WLC) device is affected by multiple vulnerabilities :

  - A denial of service vulnerability exists in the traffic
    streams metrics (TSM) implementation using Inter-Access
    Point Protocol (IAPP). An unauthenticated, adjacent
    attacker can exploit this to cause a device restart by
    sending specially crafted IAPP packets which are
    subsequently followed by an SNMP request for TSM
    information. (CVE-2016-6375)

  - A denial of service vulnerability exists in the Cisco
    Adaptive Wireless Intrusion Prevention System (wIPS)
    implementation due to improper validation of wIPS
    packets. An unauthenticated, adjacent attacker can
    exploit this, via specially crafted wIPS packets, to
    cause the device to restart. (CVE-2016-6376)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-wlc-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?470657bf");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-wlc-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a4df7fe");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in Cisco bug ID CSCuz40221 and
CSCuz40263.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
device = "Cisco Wireless LAN Controller";
model = get_kb_item("Host/Cisco/WLC/Model");
if (!empty_or_null(model))
  device += " " + model;
fix = "";

# 6.x, 7.x, 8.0.x < 8.0.140.0
if (
  version =~ "^[67]\." ||
  version =~ "^8\.0($|[^\.0-9])" ||
  version =~ "^8\.0\.([0-9]|[0-9][0-9]|1[0-3][0-9])($|[^0-9])"
)
  fix = "Upgrade to 8.0(140.0) or later.";

# 8.1 or 8.2.x < 8.2.121.0
if (
  version =~ "^8\.[12]($|[^\.0-9])" ||
  version =~ "^8\.2\.([0-9]|[0-9][0-9]|1[01][0-9]|120)($|[^0-9])"
)
  fix = "Upgrade to 8.2(121.0) or later.";

# 8.3.x < 8.3.102.0
if (
  version =~ "^8\.3($|[^\.0-9])" ||
  version =~ "^8\.3\.([0-9]|[0-9][0-9]|10[01])($|[^0-9])"
)
  fix = "Upgrade to 8.3(102.0) or later.";

if (!fix) audit(AUDIT_DEVICE_NOT_VULN, device, version);

order = make_list("Device", "Installed version", "Fixed version");
report = make_array(
  order[0], device,
  order[1], version,
  order[2], fix
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
