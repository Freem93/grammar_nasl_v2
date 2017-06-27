#TRUSTED 28b87f695e2f42f35e01147b7d3085352f6f3745dbe33da24b0584e749f1a7b8a81f70f45e9b30ec8cf3dea3e32894b920cfdf99b4491060f3a5ae4e7474437ed4f14ed442acb3bcf90ffe509f901f62e991e77cf92eacf77a5904a6e4301e82b4c7063778b321a292597a7abbdb46e52f52ab49b93be5947346e2c1a7dcd170e9b3645b9e134121ab854bff41fc78d9359f41c9b300e4e935e4b9eb97feaa548a21d0c8aad5cc8a9c67b63c7e44feef5dbcdfa0341997afff88c7b5e47b449f64bfb93037576ea9fb4a6a85d4b646b026d1537135dceffdfa23c9c6901256a6db91a79ad6fb6ec86a6546b24d64d908188a55ce3aadb88bd6a68cc8803473eef61c5dd1132248866785da65d34e995853c877dda000c95e08600f136f3616adea2822ad6b8817839e93215473610c3080456fb678170dd60745d9954e16ea00a25e40d71b302ecd21f64b38b91f2009cabf6c502b89b870f474f3be352163b51d81f66dd948ca20f1e6532bb30edb3addde1c4094bffcf543047e09c5eac61298a303fb5fc7185916e471badb704687f01bd4126ab7b12c21c843de82d2233ea66433d2aa1a754438eab329d85854d0baa658952d494b39a9642be0d443a15baaa4ea731842ec63b36389843394e6de1d5d05a7721164b35ce0d3d08cdda80fe2dc36a743672ef10b741a330a78ad3645769f8c59aa48cdeae08b91df688231
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90354);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/06");

  script_cve_id("CVE-2016-1348");
  script_osvdb_id(136246);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus55821");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-dhcpv6");

  script_name(english:"Cisco IOS XE DHCPv6 Relay Message Handling DoS (cisco-sa-20160323-dhcpv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the DHCPv6 Relay feature due to improper validation
of DHCPv6 relay messages. An unauthenticated, remote attacker can
exploit this issue, via a crafted DHCPv6 relay message, to cause the
device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7cde0b5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus55821.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.5.0S' ) flag++;
if ( ver == '3.5.1S' ) flag++;
if ( ver == '3.5.2S' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.6.3E' ) flag++;
if ( ver == '3.6.0S' ) flag++;
if ( ver == '3.6.1S' ) flag++;
if ( ver == '3.6.2S' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;
if ( ver == '3.7.0S' ) flag++;
if ( ver == '3.7.1S' ) flag++;
if ( ver == '3.7.2S' ) flag++;
if ( ver == '3.7.2tS' ) flag++;
if ( ver == '3.7.3S' ) flag++;
if ( ver == '3.7.4S' ) flag++;
if ( ver == '3.7.4aS' ) flag++;
if ( ver == '3.7.5S' ) flag++;
if ( ver == '3.7.6S' ) flag++;
if ( ver == '3.7.7S' ) flag++;
if ( ver == '3.8.0S' ) flag++;
if ( ver == '3.8.1S' ) flag++;
if ( ver == '3.8.2S' ) flag++;
if ( ver == '3.9.0S' ) flag++;
if ( ver == '3.9.0aS' ) flag++;
if ( ver == '3.9.1S' ) flag++;
if ( ver == '3.9.1aS' ) flag++;
if ( ver == '3.9.2S' ) flag++;
if ( ver == '3.10.0S' ) flag++;
if ( ver == '3.10.1S' ) flag++;
if ( ver == '3.10.1xbS' ) flag++;
if ( ver == '3.10.2S' ) flag++;
if ( ver == '3.10.3S' ) flag++;
if ( ver == '3.10.4S' ) flag++;
if ( ver == '3.10.5S' ) flag++;
if ( ver == '3.10.6S' ) flag++;
if ( ver == '3.11.0S' ) flag++;
if ( ver == '3.11.1S' ) flag++;
if ( ver == '3.11.2S' ) flag++;
if ( ver == '3.11.3S' ) flag++;
if ( ver == '3.11.4S' ) flag++;
if ( ver == '3.12.0S' ) flag++;
if ( ver == '3.12.1S' ) flag++;
if ( ver == '3.12.4S' ) flag++;
if ( ver == '3.12.2S' ) flag++;
if ( ver == '3.12.3S' ) flag++;
if ( ver == '3.13.2aS' ) flag++;
if ( ver == '3.13.0S' ) flag++;
if ( ver == '3.13.0aS' ) flag++;
if ( ver == '3.13.1S' ) flag++;
if ( ver == '3.13.2S' ) flag++;
if ( ver == '3.13.3S' ) flag++;
if ( ver == '3.13.4S' ) flag++;
if ( ver == '3.14.0S' ) flag++;
if ( ver == '3.14.1S' ) flag++;
if ( ver == '3.14.2S' ) flag++;
if ( ver == '3.14.3S' ) flag++;
if ( ver == '3.15.1cS' ) flag++;
if ( ver == '3.15.0S' ) flag++;
if ( ver == '3.15.1S' ) flag++;
if ( ver == '3.15.2S' ) flag++;
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;

# Check DHCPv6 Relay
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    if ("is in relay mode" >< buf) flag = 1;
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
      '\n  Cisco bug ID      : CSCus55821' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
