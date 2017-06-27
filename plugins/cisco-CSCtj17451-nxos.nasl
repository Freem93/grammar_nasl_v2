#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69481);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/10/18 00:11:10 $");

  script_cve_id("CVE-2011-0355");
  script_bugtraq_id(46247);
  script_osvdb_id(70837);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj17451");
  script_xref(name:"IAVB", value:"2011-B-0031");

  script_name(english:"Cisco Nexus 1000V VEM DoS (CSCtj17451)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus device is affected by a denial of service
condition when processing 802.1Q tagged packets.");
  # http://www.cisco.com/en/US/docs/switches/datacenter/nexus1000/sw/4_0_4_s_v_1_3_c/release/notes/n1000v_rn.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd22d81b");
  # http://www.cisco.com/en/US/docs/switches/datacenter/nexus1000/sw/4_2_1_s_v_1_4/release/notes/n1000v_rn.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd8cfc72");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.0(4)SV1(3c) or 4.2(1)SV1(4).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# only affects Nexus 1000V systems
if (device != 'Nexus' || model !~ '^1000[Vv]$') audit(AUDIT_HOST_NOT, "affected");

flag = 0;

if (
 version == "4.0(4)SV1(3b)" ||
 version == "4.0(4)SV1(3a)" ||
 version == "4.0(4)SV1(3)" ||
 version == "4.0(4)SV1(2)" ||
 version == "4.0(4)SV1(1)"
) flag++;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0(4)SV1(3c) / 4.2(1)SV1(4)' + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
