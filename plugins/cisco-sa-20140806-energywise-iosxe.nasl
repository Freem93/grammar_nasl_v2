#TRUSTED 946c23bc90f0d79b4bfd85f18c81e4c66498cd939e1ffbe5734380337a38088c8379450131f1103e8065f201eecc667b318333b1e985265a22eb28f9b67ab89df2e65a428ae498f2ef7830c8dbae2f21e50bd58ae729a36c4fe6f1f642ad14aa4af5887e1dd8be3c6a73aee7d400831f4491e9c75004d31a89c6fb329c7424d999b46f8cc572eb20aa332decbb717d19afb780bbcba60dbcb8b90e1945c524ed53bfee7a85b6b591c05aca79c34e6eb8147f8d38558f99d3ec9375e64a1af13c6a9ebdffafd98304a7ed73ea509c527efcc95b2b6b9e6006f23ebd14c199e2a1268bd3845da2ec59bf4c8264360cde217d8a7590e54902680f31a7cca66d4d3ab5e7bfb4c2846c008160e8583624a2b4f57b8f5ce72407ffa3960a9de91749dd3d7d41dbc851ce292c4a1644b3384407249b8f93075d75f6ff8e68c4a14b85e8d4c934af5dbd6bc18fd9f9f6b896773228d368191871b74fd0370d393e7ec956d92710536cfe2305673544282b36e130bd194239ff22cef9f04d32e36bc636d67d6a601875079febfae1c52087a6f334704ddfbeb75103dcbbe27f4f3f0665676bd492617e52fa35379aa3afd33631a3c4380280fef8aedb5fa77d6cc7535a207d5078e4d34d7125fc6a9a0ba4bab7c5572d431f2b65e60bf04eb4e0a6b9efab1758ffefc644886fef3b4400c9b9de82e699d7e18a151b0c25e364ac4a2c03d8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77154);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3327");
  script_bugtraq_id(69066);
  script_osvdb_id(109861);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup52101");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140806-energywise");

  script_name(english:"Cisco IOS XE Software EnergyWise DoS (cisco-sa-20140806-energywise");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in EnergyWise module.

The issue exists due to improper handling of specially crafted
EnergyWise packets. An unauthenticated, remote attacker could exploit
this issue to cause a device reload.

Note that this issue only affects hosts with EnergyWise enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140806-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e4f4ee3");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35091");
  # the 3.4.xSG release notes state this was fixed in 3.4.5SG, even though the advisory was not updated to state this
  # http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/release/note/OL_27989-01.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a9535d2");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# The following versions of IOS XE are vulnerable :
#   - 3.2.xXO
#   - 3.3.xSG
#   - 3.4.xSG < 3.4.5SG
#   - 3.5.[012]E
if ( ver =~ "^3\.2\.[0-9]XO$" ) flag++;
if ( ver =~ "^3\.3\.[0-9]SG$" ) flag++;
if ( ver =~ "^3\.4\.[0-4]SG$" ) flag++;
if ( ver =~ "^3\.5\.[0-2]E$" ) flag++;

# Check that EnergyWise is running since it is not
# enabled by default.
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show run | include energywise");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"energywise\s+domain", string:buf)     ||
      preg(multiline:TRUE, pattern:"energywise\s+management", string:buf) ||
      preg(multiline:TRUE, pattern:"energywise\s+endpoint", string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup52101' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
