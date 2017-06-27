#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69058);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/25 14:51:24 $");

  script_name(english:"Cisco ONS Detection");
  script_summary(english:"Detects Cisco ONS products");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a Cisco Optical Networking System device.");
  script_set_attribute(
    attribute:"description",
    value:
"Based on the SNMP sysDesc value returned from the remote host, it is a
Cisco Optical Networking System device."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/hw/optical/ps2011/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ons");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("snmp_sysDesc.nasl");
  script_require_ports("SNMP/sysDesc");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

desc = get_kb_item_or_exit("SNMP/sysDesc");
if ("Cisco ONS" >!< desc) audit(AUDIT_NOT_DETECT, "Cisco ONS");

item = eregmatch(pattern:"Cisco ONS ([A-Z0-9-]+) ([A-Z0-9.-]+) ", string:desc);
if (isnull(item)) exit(1, "Error parsing device and version from SNMP sysDesc.");

set_kb_item(name: "Cisco/ONS/Device", value: item[1]);
set_kb_item(name: "Cisco/ONS/Version", value: item[2]);

if (report_verbosity > 0)
{
  report = '\n  Device           : ' + item[1] +
           '\n  Software version : ' + item[2] + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
