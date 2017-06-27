#TRUSTED 596a4c4f3cbe9bea465681510d50e1133f2f12e523fc07fd951a7e6de4b0bf0f692b18d7f1edada7468dd6199969df52966b39e84ff76dde5b557ec0f27b67f8353b070db23b20139ac18308794440f493ed771770bca94a459a13c09173e53397af4bb0b652eb20da9c3651b807f475bc8e2535b31b76c89e81bd100115fee1539ef324409463881a3d95b5ebf64fdaa478fbab3e131ef57d5e3223ee7a6bc1c176046d4a31b8601a19325a35b7bdbb3d433e726232f0b16370f0e6cc0bee861737ec83682835734fd8a8bb8a7120ab4567795dcd9c938ff822ad3234ee26215fc1d796cf7894f1312f68e0067f9429e8e14b28b222c665b61e0315c227501167ff4b893c3b8a1ffe16be0348e008bb8629c22f57cfba7ef48025e80f734e1780bddbf6c54b67316101e979bb2184a26de4a649b4e8a2200a1f4e5963ed4ea3ec51831ec4e7901956ae2244ac1f2e7c0de9d72f36259d5033ea3f7b264e9370b27546db2d3ad2a564d19392da16c21a442230124ab5c6e333e1fb99137b9adf5b7c6c97d65d0dbc5789d74c14f526117dc190de6658f4d4f702dc13d7f3dd11f549170b90d93ece337f48d9605d4d08a9c20d4c78a6b36d35c18135830e15bcdb0bef113e52a1cb67025620f3826369a07c6e36275a6daaabe80c07fa3593167bcb61d0b1fe9ef188d9c1753507ffe08a80230ea8f1dbbe8bbb0d5b98a9ad10
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82666);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0686");
  script_bugtraq_id(73895);
  script_osvdb_id(120294);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq92240");

  script_name(english:"Cisco Nexus 9000 Series Platform Manager Service DoS");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus device is affected by a denial of service
vulnerability in the Platform Manager service, part of the SNMP
subsystem, when the High Availability (HA) policy is configured to
Reset. A remote, authenticated attacker can exploit this to trigger a
device reload.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38193");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuq92240.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/09");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# only affects nexus 9000 series systems
if (device != 'Nexus' || model !~ '^9[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

flag = 0;
override = 0;

if (version == "6.1(2)I2(3)") flag++;

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_version",
                              "show version");
  if (check_cisco_result(buf))
  {
    if (!preg(multiline:TRUE, pattern:"hap reset", string:buf)) { flag++; }
  } else if (cisco_needs_enable(buf)) { flag++; override++; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1(2)I3(1)' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
