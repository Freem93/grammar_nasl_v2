#TRUSTED 222a93f37b0cc29e89868907921de19790ca5d780a0ee5d01e9ae9f20c23be966c965a677055a79d65924c85d5d203e2f116c003f23755402faa26fc0b4c4b6e8c7eeaab9ecff3dfdfbe4ae73594885642a0550c7f8ca00e747202ea91acabec230b51c2f872df3b5313ad566f5e856c214c4abba89dca71a9f707954978d956d1c402592f8e2074edaed01860441d3e68458d58ea2110d2ebecca00619b39812471ec4fa0c8a6e990597a88c2119ba8116e732a386c4feac228ddb4181e37247325788e115a623c83fbd3041a5c24bb16d63b29735fb3a28faa00f9c55996236d6fd78583d7f88aeddb4657ee9c5b122676b04b6927229550cf37d97dde7624eee388ed33bc209fa5a78578caf8ad03bb22c00fa53fb521e2f9d79453b16b9dfeaaa490362776c8aa0a0afb734292e71ded5b1e76f3200b70ce33e24abcbb34b049a9790c0b40ead9b3b10acccac47d580df2c41cc3f188366b24c1d8ef44c67011c2524e9ae2721c52a8d9f7c492755893bb6e4cc51bbba1d648b6807350e6fdc189705dbfd3bc79499657de36006fdfe809bfd5d6842d147c428d04ae1ae935843897bceee9abcdd8e058e1b17c12880c02cf2eae91711602ac09536591a9b35d5fee2a77384755bfe6c128e87752aaceffcb2a3d420cb4b7ff17042f265dcd5c35e0deed3c54ac70f57454a227f64bfc5aae02372b844713060a4728460f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93898);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/24");

  script_cve_id("CVE-2016-6382", "CVE-2016-6392");
  script_bugtraq_id(93211);
  script_osvdb_id(144899, 144900);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud36767");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy16399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-msdp");

  script_name(english:"Cisco IOS XE Multicast Routing Multiple DoS (cisco-sa-20160928-msdp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Cisco IOS XE device is affected by multiple denial of service
vulnerabilities :

  - A denial of service vulnerability exists due to improper
    validation of packets encapsulated in a PIM register
    message. An unauthenticated, remote attacker can exploit
    this, by sending an IPv6 PIM register packet to a PIM
    rendezvous point (RP), to cause the device to restart.
    (CVE-2016-6382)

  - A denial of service vulnerability exists in the IPv4
    Multicast Source Discovery Protocol (MSDP)
    implementation due to improper validation of
    Source-Active (SA) messages received from a configured
    MSDP peer. An unauthenticated, remote attacker can
    exploit this to cause the device to restart.
    (CVE-2016-6392)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-msdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72b1793a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCud36767");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy16399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20160928-msdp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

if (version == "3.2.0JA") flag = 1;
else if (version == "3.8.0E") flag = 1;
else if (version == "3.8.1E") flag = 1;
else if (version == "3.1.3aS") flag = 1;
else if (version == "3.1.0S") flag = 1;
else if (version == "3.1.1S") flag = 1;
else if (version == "3.1.2S") flag = 1;
else if (version == "3.1.4S") flag = 1;
else if (version == "3.1.4aS") flag = 1;
else if (version == "3.2.1S") flag = 1;
else if (version == "3.2.2S") flag = 1;
else if (version == "3.2.0SE") flag = 1;
else if (version == "3.2.1SE") flag = 1;
else if (version == "3.2.2SE") flag = 1;
else if (version == "3.2.3SE") flag = 1;
else if (version == "3.3.0S") flag = 1;
else if (version == "3.3.1S") flag = 1;
else if (version == "3.3.2S") flag = 1;
else if (version == "3.3.0SE") flag = 1;
else if (version == "3.3.1SE") flag = 1;
else if (version == "3.3.2SE") flag = 1;
else if (version == "3.3.3SE") flag = 1;
else if (version == "3.3.4SE") flag = 1;
else if (version == "3.3.5SE") flag = 1;
else if (version == "3.3.0SG") flag = 1;
else if (version == "3.3.1SG") flag = 1;
else if (version == "3.3.2SG") flag = 1;
else if (version == "3.3.0XO") flag = 1;
else if (version == "3.3.1XO") flag = 1;
else if (version == "3.3.2XO") flag = 1;
else if (version == "3.4.0S") flag = 1;
else if (version == "3.4.0aS") flag = 1;
else if (version == "3.4.1S") flag = 1;
else if (version == "3.4.2S") flag = 1;
else if (version == "3.4.3S") flag = 1;
else if (version == "3.4.4S") flag = 1;
else if (version == "3.4.5S") flag = 1;
else if (version == "3.4.6S") flag = 1;
else if (version == "3.4.0SG") flag = 1;
else if (version == "3.4.1SG") flag = 1;
else if (version == "3.4.2SG") flag = 1;
else if (version == "3.4.3SG") flag = 1;
else if (version == "3.4.4SG") flag = 1;
else if (version == "3.4.5SG") flag = 1;
else if (version == "3.4.6SG") flag = 1;
else if (version == "3.4.7SG") flag = 1;
else if (version == "3.5.0E") flag = 1;
else if (version == "3.5.1E") flag = 1;
else if (version == "3.5.2E") flag = 1;
else if (version == "3.5.3E") flag = 1;
else if (version == "3.5.0S") flag = 1;
else if (version == "3.5.1S") flag = 1;
else if (version == "3.5.2S") flag = 1;
else if (version == "3.6.4E") flag = 1;
else if (version == "3.6.0E") flag = 1;
else if (version == "3.6.1E") flag = 1;
else if (version == "3.6.2aE") flag = 1;
else if (version == "3.6.2E") flag = 1;
else if (version == "3.6.3E") flag = 1;
else if (version == "3.6.0S") flag = 1;
else if (version == "3.6.1S") flag = 1;
else if (version == "3.6.2S") flag = 1;
else if (version == "3.7.3E") flag = 1;
else if (version == "3.7.0E") flag = 1;
else if (version == "3.7.1E") flag = 1;
else if (version == "3.7.2E") flag = 1;
else if (version == "3.7.0S") flag = 1;
else if (version == "3.7.1S") flag = 1;
else if (version == "3.7.2S") flag = 1;
else if (version == "3.7.2tS") flag = 1;
else if (version == "3.7.3S") flag = 1;
else if (version == "3.7.4S") flag = 1;
else if (version == "3.7.4aS") flag = 1;
else if (version == "3.7.5S") flag = 1;
else if (version == "3.7.6S") flag = 1;
else if (version == "3.7.7S") flag = 1;
else if (version == "3.8.0S") flag = 1;
else if (version == "3.8.1S") flag = 1;
else if (version == "3.8.2S") flag = 1;
else if (version == "3.9.0S") flag = 1;
else if (version == "3.9.0aS") flag = 1;
else if (version == "3.9.1S") flag = 1;
else if (version == "3.9.1aS") flag = 1;
else if (version == "3.9.2S") flag = 1;
else if (version == "3.10.0S") flag = 1;
else if (version == "3.10.1S") flag = 1;
else if (version == "3.10.1xbS") flag = 1;
else if (version == "3.10.2S") flag = 1;
else if (version == "3.10.2tS") flag = 1;
else if (version == "3.10.3S") flag = 1;
else if (version == "3.10.4S") flag = 1;
else if (version == "3.10.5S") flag = 1;
else if (version == "3.10.6S") flag = 1;
else if (version == "3.10.7S") flag = 1;
else if (version == "3.11.0S") flag = 1;
else if (version == "3.11.1S") flag = 1;
else if (version == "3.11.2S") flag = 1;
else if (version == "3.11.3S") flag = 1;
else if (version == "3.11.4S") flag = 1;
else if (version == "3.12.0S") flag = 1;
else if (version == "3.12.0aS") flag = 1;
else if (version == "3.12.1S") flag = 1;
else if (version == "3.12.4S") flag = 1;
else if (version == "3.12.2S") flag = 1;
else if (version == "3.12.3S") flag = 1;
else if (version == "3.13.2aS") flag = 1;
else if (version == "3.13.5aS") flag = 1;
else if (version == "3.13.5S") flag = 1;
else if (version == "3.13.0S") flag = 1;
else if (version == "3.13.0aS") flag = 1;
else if (version == "3.13.1S") flag = 1;
else if (version == "3.13.2S") flag = 1;
else if (version == "3.13.3S") flag = 1;
else if (version == "3.13.4S") flag = 1;
else if (version == "3.14.0S") flag = 1;
else if (version == "3.14.1S") flag = 1;
else if (version == "3.14.2S") flag = 1;
else if (version == "3.14.3S") flag = 1;
else if (version == "3.15.1cS") flag = 1;
else if (version == "3.15.0S") flag = 1;
else if (version == "3.15.1S") flag = 1;
else if (version == "3.15.2S") flag = 1;
else if (version == "3.17.1aS") flag = 1;
else if (version == "3.17.0S") flag = 1;
else if (version == "3.17.1S") flag = 1;
else if (version == "16.1.1") flag = 1;
else if (version == "16.1.2") flag = 1;
else if (version == "3.16.2bS") flag = 1;
else if (version == "3.16.0S") flag = 1;
else if (version == "3.16.0cS") flag = 1;
else if (version == "3.16.1S") flag = 1;
else if (version == "3.16.1aS") flag = 1;
else if (version == "3.16.2S") flag = 1;
else if (version == "3.16.2aS") flag = 1;

cmds = make_list();
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include ip msdp peer", "show running-config | include ip msdp peer");
    if (check_cisco_result(buf))
    {
      # Vulnerable if msdp enabled
      if (preg(pattern:"\s*ip\s*msdp\s*peer\s*[0-9]{1,3}(\.[0-9]{1,3}){3}", multiline:TRUE, string:buf))
      {
        flag = 1;
        cmds = make_list(cmds, "show running-config | include ip msdp peer");
      }

      buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include include ipv6 multicast-routing", "show running-config | include ipv6 multicast-routing");
      if (check_cisco_result(buf2))
      {
        # Vulnerable if ipv6 multicast routing enabled
        if (preg(pattern:"\s*ipv6\s*multicast-routing", multiline:TRUE, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, "show running-config | include ipv6 multicast-routing");
        }
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCud36767, CSCuy16399",
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
