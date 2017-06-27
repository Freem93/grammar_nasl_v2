#TRUSTED 3a16aa373dced1da20fcb589188f1bc45edfe1fe7bda22ca7bba331496b2c9ebbcfef4a63d55fc9223f7399dae3eeb84ab323d699c0c251b55eb92d859cfbdccba8f3ffc9c5acc01f69a54c21466a89dae916dd2a341a0b7cc06addfe7007880fe6b094be3ad9c2b895eeb7bd4cafc1156e079bac3330cf74aba3b40e7c440876a65a24ea1b4f57cca2f8c0bd44cf95aefebb09d4c81386269bc1e97bda5dd2ea1e9ef72d8854ab1ffecdaf1ceb7e87ffd1b1479cbac7a165d03a18b403acf276958e8f3bf9d513b6c2849afe64b15bbf7d821af53e6df0fbd19760e1d9496364b86571fb101b1b23f62a7bd36d29cdaa40887db7e99948e194a6cf33f85081ae18cfc0c65a0478c97e1903cb7833ebc5b0f3cb5a35e6ce564c6beef8df6c89d54cff10ab5ce68d636bc8c77fa8f91126c2cc750e7b1bc1e763a7e532125a3a938cbbef48474f048cfe8bdd5c7be433e969264659cc13f2f22dcf32f114f5495054ed7d85e478d1cb09c10855a4e37d3957f4c0c82f3fec6f63b5b35b46e2f7828790825b84dd197c4fce1701fcd6800a0d08858f90a3497000f7a90a1e77c54bc81079117569f6fb32c7d74ade779a33bef993a7bc0b75f0e5257a23bb74b271c901ba06f0ec0ab32f1e17836c3a0a18964337bd85fb31cb87d50e23d10ac098748ad57d418bf306777ac1f300c98f63b68b356176233a29319d5be7e46daf9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99687);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/26");

  script_cve_id(
    "CVE-2017-3860",
    "CVE-2017-3861",
    "CVE-2017-3862",
    "CVE-2017-3863"
  );
  script_bugtraq_id(97935);
  script_osvdb_id(
    155944,
    155945,
    155946,
    155947
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut47751");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut50727");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu76493");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-energywise");

  script_name(english:"Cisco IOS EnergyWise DoS (cisco-sa-20170419-energywise)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by multiple buffer overflow
conditions due to improper parsing of EnergyWise packets. An
unauthenticated, remote attacker can exploit these, by sending
specially crafted IPv4 EnergyWise packets to the device, to cause a
denial of service condition. Note that IPv6 packets cannot be used to
exploit these issues and that the EnergyWise feature is not enabled by
default on Cisco IOS devices.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d2ebdad");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCur29331");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut47751");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut50727");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu76493");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20170419-energywise.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln versions
if (
  ver == '12.2(33)SXI10' ||
  ver == '12.2(33)SXI11' ||
  ver == '12.2(33)SXI12' ||
  ver == '12.2(33)SXI13' ||
  ver == '12.2(33)SXI14' ||
  ver == '12.2(33)SXI4' ||
  ver == '12.2(33)SXI4a' ||
  ver == '12.2(33)SXI5' ||
  ver == '12.2(33)SXI5a' ||
  ver == '12.2(33)SXI6' ||
  ver == '12.2(33)SXI7' ||
  ver == '12.2(33)SXI8' ||
  ver == '12.2(33)SXI8a' ||
  ver == '12.2(33)SXI9' ||
  ver == '12.2(33)SXI9a' ||
  ver == '12.2(33)SXJ' ||
  ver == '12.2(33)SXJ1' ||
  ver == '12.2(33)SXJ10' ||
  ver == '12.2(33)SXJ2' ||
  ver == '12.2(33)SXJ3' ||
  ver == '12.2(33)SXJ4' ||
  ver == '12.2(33)SXJ5' ||
  ver == '12.2(33)SXJ6' ||
  ver == '12.2(33)SXJ7' ||
  ver == '12.2(33)SXJ8' ||
  ver == '12.2(33)SXJ9' ||
  ver == '12.2(52)EX' ||
  ver == '12.2(52)EX1' ||
  ver == '12.2(52)EY' ||
  ver == '12.2(52)EY1' ||
  ver == '12.2(52)EY1A' ||
  ver == '12.2(52)EY1b' ||
  ver == '12.2(52)EY1c' ||
  ver == '12.2(52)EY2' ||
  ver == '12.2(52)EY2a' ||
  ver == '12.2(52)EY3' ||
  ver == '12.2(52)EY3a' ||
  ver == '12.2(52)EY4' ||
  ver == '12.2(52)SE' ||
  ver == '12.2(52)SE1' ||
  ver == '12.2(53)EX' ||
  ver == '12.2(53)EY' ||
  ver == '12.2(53)EZ' ||
  ver == '12.2(53)SE' ||
  ver == '12.2(53)SE1' ||
  ver == '12.2(53)SE2' ||
  ver == '12.2(54)SE' ||
  ver == '12.2(54)SG' ||
  ver == '12.2(54)SG1' ||
  ver == '12.2(54)WO' ||
  ver == '12.2(54)XO' ||
  ver == '12.2(55)EX' ||
  ver == '12.2(55)EX1' ||
  ver == '12.2(55)EX2' ||
  ver == '12.2(55)EX3' ||
  ver == '12.2(55)EY' ||
  ver == '12.2(55)EZ' ||
  ver == '12.2(55)SE' ||
  ver == '12.2(55)SE1' ||
  ver == '12.2(55)SE10' ||
  ver == '12.2(55)SE11' ||
  ver == '12.2(55)SE2' ||
  ver == '12.2(55)SE3' ||
  ver == '12.2(55)SE4' ||
  ver == '12.2(55)SE5' ||
  ver == '12.2(55)SE6' ||
  ver == '12.2(55)SE7' ||
  ver == '12.2(55)SE8' ||
  ver == '12.2(55)SE9' ||
  ver == '12.2(58)EY' ||
  ver == '12.2(58)EY1' ||
  ver == '12.2(58)EY2' ||
  ver == '12.2(58)SE' ||
  ver == '12.2(58)SE1' ||
  ver == '12.2(58)SE2' ||
  ver == '12.2(60)EZ' ||
  ver == '12.2(60)EZ1' ||
  ver == '12.2(60)EZ2' ||
  ver == '12.2(60)EZ3' ||
  ver == '12.2(60)EZ4' ||
  ver == '12.2(60)EZ5' ||
  ver == '12.2(60)EZ6' ||
  ver == '12.2(60)EZ7' ||
  ver == '12.2(60)EZ8' ||
  ver == '12.2(60)EZ9' ||
  ver == '15.0(1)M10' ||
  ver == '15.0(1)M2' ||
  ver == '15.0(1)M3' ||
  ver == '15.0(1)M4' ||
  ver == '15.0(1)M5' ||
  ver == '15.0(1)M6' ||
  ver == '15.0(1)M6a' ||
  ver == '15.0(1)M7' ||
  ver == '15.0(1)M8' ||
  ver == '15.0(1)M9' ||
  ver == '15.0(1)SE' ||
  ver == '15.0(1)SE1' ||
  ver == '15.0(1)SE2' ||
  ver == '15.0(1)SE3' ||
  ver == '15.0(1)SY1' ||
  ver == '15.0(1)SY10' ||
  ver == '15.0(1)SY2' ||
  ver == '15.0(1)SY3' ||
  ver == '15.0(1)SY4' ||
  ver == '15.0(1)SY5' ||
  ver == '15.0(1)SY6' ||
  ver == '15.0(1)SY7' ||
  ver == '15.0(1)SY7a' ||
  ver == '15.0(1)SY8' ||
  ver == '15.0(1)SY9' ||
  ver == '15.0(1)XO' ||
  ver == '15.0(1)XO1' ||
  ver == '15.0(2)ED' ||
  ver == '15.0(2)ED1' ||
  ver == '15.0(2)EH' ||
  ver == '15.0(2)EJ' ||
  ver == '15.0(2)EJ1' ||
  ver == '15.0(2)EK' ||
  ver == '15.0(2)EK1' ||
  ver == '15.0(2)EX' ||
  ver == '15.0(2)EX1' ||
  ver == '15.0(2)EX10' ||
  ver == '15.0(2)EX2' ||
  ver == '15.0(2)EX3' ||
  ver == '15.0(2)EX4' ||
  ver == '15.0(2)EX5' ||
  ver == '15.0(2)EX6' ||
  ver == '15.0(2)EX7' ||
  ver == '15.0(2)EX8' ||
  ver == '15.0(2)EZ' ||
  ver == '15.0(2)SE' ||
  ver == '15.0(2)SE1' ||
  ver == '15.0(2)SE10' ||
  ver == '15.0(2)SE2' ||
  ver == '15.0(2)SE3' ||
  ver == '15.0(2)SE4' ||
  ver == '15.0(2)SE5' ||
  ver == '15.0(2)SE6' ||
  ver == '15.0(2)SE7' ||
  ver == '15.0(2)SE9' ||
  ver == '15.0(2)SG' ||
  ver == '15.0(2)SG1' ||
  ver == '15.0(2)SG2' ||
  ver == '15.0(2)SG3' ||
  ver == '15.0(2)SG4' ||
  ver == '15.0(2)SG5' ||
  ver == '15.0(2)SG6' ||
  ver == '15.0(2)SG7' ||
  ver == '15.0(2)SG8' ||
  ver == '15.0(2)XO' ||
  ver == '15.0(2a)EX5' ||
  ver == '15.0(2a)SE9' ||
  ver == '15.1(1)SG' ||
  ver == '15.1(1)SG1' ||
  ver == '15.1(1)SG2' ||
  ver == '15.1(1)SY' ||
  ver == '15.1(1)SY2' ||
  ver == '15.1(1)SY3' ||
  ver == '15.1(1)SY4' ||
  ver == '15.1(1)SY5' ||
  ver == '15.1(1)SY6' ||
  ver == '15.1(1)T' ||
  ver == '15.1(1)T1' ||
  ver == '15.1(1)T2' ||
  ver == '15.1(1)T3' ||
  ver == '15.1(1)T4' ||
  ver == '15.1(1)T5' ||
  ver == '15.1(1)XB1' ||
  ver == '15.1(1)XB2' ||
  ver == '15.1(1)XB3' ||
  ver == '15.1(2)GC' ||
  ver == '15.1(2)GC1' ||
  ver == '15.1(2)GC2' ||
  ver == '15.1(2)SG' ||
  ver == '15.1(2)SG1' ||
  ver == '15.1(2)SG2' ||
  ver == '15.1(2)SG3' ||
  ver == '15.1(2)SG4' ||
  ver == '15.1(2)SG5' ||
  ver == '15.1(2)SG6' ||
  ver == '15.1(2)SG7' ||
  ver == '15.1(2)SG8' ||
  ver == '15.1(2)SY' ||
  ver == '15.1(2)SY1' ||
  ver == '15.1(2)SY10' ||
  ver == '15.1(2)SY2' ||
  ver == '15.1(2)SY3' ||
  ver == '15.1(2)SY4' ||
  ver == '15.1(2)SY4a' ||
  ver == '15.1(2)SY5' ||
  ver == '15.1(2)SY6' ||
  ver == '15.1(2)SY7' ||
  ver == '15.1(2)SY8' ||
  ver == '15.1(2)T' ||
  ver == '15.1(2)T0a' ||
  ver == '15.1(2)T1' ||
  ver == '15.1(2)T2' ||
  ver == '15.1(2)T2a' ||
  ver == '15.1(2)T3' ||
  ver == '15.1(2)T4' ||
  ver == '15.1(2)T5' ||
  ver == '15.1(3)T' ||
  ver == '15.1(3)T1' ||
  ver == '15.1(3)T2' ||
  ver == '15.1(3)T3' ||
  ver == '15.1(3)T4' ||
  ver == '15.1(4)GC' ||
  ver == '15.1(4)GC1' ||
  ver == '15.1(4)GC2' ||
  ver == '15.1(4)M' ||
  ver == '15.1(4)M0a' ||
  ver == '15.1(4)M0b' ||
  ver == '15.1(4)M1' ||
  ver == '15.1(4)M10' ||
  ver == '15.1(4)M11' ||
  ver == '15.1(4)M12' ||
  ver == '15.1(4)M12a' ||
  ver == '15.1(4)M2' ||
  ver == '15.1(4)M3' ||
  ver == '15.1(4)M3a' ||
  ver == '15.1(4)M4' ||
  ver == '15.1(4)M5' ||
  ver == '15.1(4)M6' ||
  ver == '15.1(4)M7' ||
  ver == '15.1(4)M8' ||
  ver == '15.1(4)M9' ||
  ver == '15.1(4)XB4' ||
  ver == '15.1(4)XB5' ||
  ver == '15.1(4)XB5a' ||
  ver == '15.1(4)XB6' ||
  ver == '15.1(4)XB7' ||
  ver == '15.1(4)XB8' ||
  ver == '15.1(4)XB8a' ||
  ver == '15.2(1)E' ||
  ver == '15.2(1)E1' ||
  ver == '15.2(1)E2' ||
  ver == '15.2(1)E3' ||
  ver == '15.2(1)GC' ||
  ver == '15.2(1)GC1' ||
  ver == '15.2(1)GC2' ||
  ver == '15.2(1)SY' ||
  ver == '15.2(1)SY0a' ||
  ver == '15.2(1)SY1' ||
  ver == '15.2(1)SY1a' ||
  ver == '15.2(1)SY2' ||
  ver == '15.2(1)SY3' ||
  ver == '15.2(1)T' ||
  ver == '15.2(1)T1' ||
  ver == '15.2(1)T2' ||
  ver == '15.2(1)T3' ||
  ver == '15.2(1)T3a' ||
  ver == '15.2(1)T4' ||
  ver == '15.2(2)E' ||
  ver == '15.2(2)E1' ||
  ver == '15.2(2)E2' ||
  ver == '15.2(2)E4' ||
  ver == '15.2(2)E5' ||
  ver == '15.2(2)E5a' ||
  ver == '15.2(2)EA1' ||
  ver == '15.2(2)EA2' ||
  ver == '15.2(2)EA3' ||
  ver == '15.2(2)EB' ||
  ver == '15.2(2)EB1' ||
  ver == '15.2(2)EB2' ||
  ver == '15.2(2)GC' ||
  ver == '15.2(2)SY' ||
  ver == '15.2(2)SY1' ||
  ver == '15.2(2)SY2' ||
  ver == '15.2(2)T' ||
  ver == '15.2(2)T1' ||
  ver == '15.2(2)T2' ||
  ver == '15.2(2)T3' ||
  ver == '15.2(2)T4' ||
  ver == '15.2(2a)E1' ||
  ver == '15.2(2b)E' ||
  ver == '15.2(3)E' ||
  ver == '15.2(3)E1' ||
  ver == '15.2(3)E2' ||
  ver == '15.2(3)E3' ||
  ver == '15.2(3)EA' ||
  ver == '15.2(3)GC' ||
  ver == '15.2(3)GC1' ||
  ver == '15.2(3)GCA' ||
  ver == '15.2(3)GCA1' ||
  ver == '15.2(3)T' ||
  ver == '15.2(3)T1' ||
  ver == '15.2(3)T2' ||
  ver == '15.2(3)T3' ||
  ver == '15.2(3)T4' ||
  ver == '15.2(3)XA' ||
  ver == '15.2(3a)E' ||
  ver == '15.2(3m)E2' ||
  ver == '15.2(3m)E7' ||
  ver == '15.2(4)E' ||
  ver == '15.2(4)EA' ||
  ver == '15.2(4)GC' ||
  ver == '15.2(4)GC1' ||
  ver == '15.2(4)GC2' ||
  ver == '15.2(4)GC3' ||
  ver == '15.2(4)M' ||
  ver == '15.2(4)M1' ||
  ver == '15.2(4)M10' ||
  ver == '15.2(4)M11' ||
  ver == '15.2(4)M2' ||
  ver == '15.2(4)M3' ||
  ver == '15.2(4)M4' ||
  ver == '15.2(4)M5' ||
  ver == '15.2(4)M6' ||
  ver == '15.2(4)M6a' ||
  ver == '15.2(4)M6b' ||
  ver == '15.2(4)M7' ||
  ver == '15.2(4)M8' ||
  ver == '15.2(4)M9' ||
  ver == '15.2(4)XB10' ||
  ver == '15.2(4)XB11' ||
  ver == '15.3(0)SY' ||
  ver == '15.3(1)SY' ||
  ver == '15.3(1)SY2' ||
  ver == '15.3(1)T' ||
  ver == '15.3(1)T1' ||
  ver == '15.3(1)T2' ||
  ver == '15.3(1)T3' ||
  ver == '15.3(1)T4' ||
  ver == '15.3(2)T' ||
  ver == '15.3(2)T1' ||
  ver == '15.3(2)T2' ||
  ver == '15.3(2)T3' ||
  ver == '15.3(2)T4' ||
  ver == '15.3(3)M' ||
  ver == '15.3(3)M1' ||
  ver == '15.3(3)M2' ||
  ver == '15.3(3)M3' ||
  ver == '15.3(3)M4' ||
  ver == '15.3(3)M5' ||
  ver == '15.3(3)M6' ||
  ver == '15.3(3)M7' ||
  ver == '15.3(3)M9' ||
  ver == '15.3(3)XB12' ||
  ver == '15.4(1)CG' ||
  ver == '15.4(1)CG1' ||
  ver == '15.4(1)SY' ||
  ver == '15.4(1)SY1' ||
  ver == '15.4(1)T' ||
  ver == '15.4(1)T1' ||
  ver == '15.4(1)T2' ||
  ver == '15.4(1)T3' ||
  ver == '15.4(1)T4' ||
  ver == '15.4(2)CG' ||
  ver == '15.4(2)T' ||
  ver == '15.4(2)T1' ||
  ver == '15.4(2)T2' ||
  ver == '15.4(2)T3' ||
  ver == '15.4(2)T4' ||
  ver == '15.4(3)M' ||
  ver == '15.4(3)M1' ||
  ver == '15.4(3)M2' ||
  ver == '15.4(3)M3' ||
  ver == '15.4(3)M4' ||
  ver == '15.4(3)M5' ||
  ver == '15.4(3)M6' ||
  ver == '15.4(3)M6a' ||
  ver == '15.4(3)M7' ||
  ver == '15.4(3)M7a' ||
  ver == '15.5(1)T' ||
  ver == '15.5(1)T1' ||
  ver == '15.5(1)T2' ||
  ver == '15.5(1)T3' ||
  ver == '15.5(1)T4' ||
  ver == '15.5(2)T' ||
  ver == '15.5(2)T1' ||
  ver == '15.5(2)T2' ||
  ver == '15.5(2)T3' ||
  ver == '15.5(2)T4' ||
  ver == '15.5(2)XB' ||
  ver == '15.5(3)M0a' ||
  ver == '15.5(3)M1' ||
  ver == '15.5(3)M2' ||
  ver == '15.5(3)M2a' ||
  ver == '15.5(3)M4' ||
  ver == '15.5(3)M4a' ||
  ver == '15.5(3)M4b' ||
  ver == '15.5(3)M4c' ||
  ver == '15.5(3)M5' ||
  ver == '15.5(3)S5' ||
  ver == '15.6(1)T' ||
  ver == '15.6(1)T0a' ||
  ver == '15.6(1)T1' ||
  ver == '15.6(1)T2' ||
  ver == '15.6(2)T' ||
  ver == '15.6(2)T1' ||
  ver == '15.6(2)T2' ||
  ver == '15.6(3)M' ||
  ver == '15.6(3)M0a' ||
  ver == '15.6(3)M1' ||
  ver == '15.6(3)M1a' ||
  ver == '15.6(3)M1b' ||
  ver == '15.6(3)M2'
) flag++;

cmds = make_list();
# Check that device is configured with EnergyWise support
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show run | include energywise", "show run | include energywise");
  if (check_cisco_result(buf))
  {
    if ("energywise" >< buf)
    {
      cmds = make_list(cmds, "show run | include energywise");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCur29331, CSCut47751, CSCut50727, CSCuu76493",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
