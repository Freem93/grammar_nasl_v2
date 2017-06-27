#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99473);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/19 14:12:03 $");

  script_cve_id("CVE-2016-9219");
  script_bugtraq_id(97423);
  script_osvdb_id(155015);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170405-wlc2");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva98592");

  script_name(english:"Cisco Wireless LAN Controller IPv6 UDP Packet Handling DoS (cisco-sa-20170405-wlc2)");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN
Controller (WLC) software running on the remote device is affected by
a denial of service vulnerability in the IPv6 UDP ingress packet
processing functionality due to incomplete IPv6 UDP header validation.
An unauthenticated, remote attacker can exploit this, via a specially
crafted IPv6 UDP packet, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-wlc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72db09c5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva98592");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva98592.");
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

# Only affects 8.2.121.0 and 8.3.102.0
if (version == "8.2.121.0")
  fix = "Upgrade to 8.2(130.0) or later.";
else if (version == "8.3.102.0")
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
