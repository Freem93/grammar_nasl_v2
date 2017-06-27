#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99472);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/19 14:12:03 $");

  script_cve_id("CVE-2016-9195", "CVE-2017-3832");
  script_bugtraq_id(97421, 97425);
  script_osvdb_id(155007, 155020);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170405-wlc1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170405-wlc3");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb01835");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb48198");

  script_name(english:"Cisco Wireless LAN Controller Multiple DoS");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN
Controller (WLC) software running on the remote device is affected by
multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the RADIUS
    Change of Authorization (CoA) request processing due to
    improper validation of the RADIUS CoA packet header. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RADIUS CoA packet, to disconnect
    connections through the WLC. (CVE-2016-9195)

  - A denial of service vulnerability exists in the web
    management interface due to a missing internal handler
    for a specific request. An unauthenticated, remote
    attacker can exploit this, by accessing a hidden URL on
    the web management interface, to cause the device to
    reload. (CVE-2017-3832)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-wlc1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a98ac301");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-wlc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bc8cd49");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb01835");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb48198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvb01835 and CSCvb48198.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

# Only affects 8.3.102.0
if (version == "8.3.102.0")
  fix = "Upgrade to 8.3(111.0) or later.";

if (!fix) audit(AUDIT_DEVICE_NOT_VULN, device, version);

order = make_list("Device", "Installed version", "Fixed version");
report = make_array(
  order[0], device,
  order[1], version,
  order[2], fix
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
