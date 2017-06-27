#TRUSTED 15e17cfa3fb8f880d2a74b0a5fd49cce42322696c099464423a714abd296690e5e81418dfee457650d17ad1c1aec195898be57f08bcc19e0e69a495f69470830837e85efbe5466e5b6f8f3ef950ec596c904c423e7456023cdb4e1d33015b56523a199f70c52054157b3c366549c8318ebccbbfc8d9591fb427f3bcd58a805e17e5cfa87065af621e642496717a0912e7194e3ce9aebbab027d142f0569cf7cb4252110f792f3c4d5558731fcb2c29956e9186b164509dd86b3cab838d686b4bc53b6a2c980888127c939f6af688f44903b22517bb7ca23d5cc67104fa9500bbfeee0f76b5ed555c61c1a1fd022c47474559af5b4a8a03793f509ef75e0e64ed271d1b21f1dfa0b71fe7e6091eb829cdfb43bbeadca119a9a22964c718b834764475698abbb1b254ee30c0f41f12e69a30a36d25a6c3820825acc488b3c51f62535e81746de3eb672f1cb479114336a7a20d9f0a3543617c264f59068326321c1305016112a65ed6083036a827da0198664b10afa435a1f1d47b1140087bb3b696dc018dbbb9941516655e16838ea71eb658b3a0582c13e29e7f13bb00dfe87e7d1823237a1f452fd39bf8645dcf8b8d63a7d7fd8dcee0df71092f2db3c7107d1f48ba49f0756b391656d38a618fcf13ae342d49993ab99a108b05419167b63fa99b7f0f06d323123cd478b013f7bd9f4325f961016ffc706030f92bb8bc6d4a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82586);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/08/02");

  script_cve_id("CVE-2015-0639");
  script_bugtraq_id(73337);
  script_osvdb_id(119945);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua79665");

  script_name(english:"Cisco IOS XE Common Flow Table DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability in the Common Flow Table (CFT)
feature due to improper processing of IPv6 packets encapsulated inside
IPv4 UDP packets. An unauthenticated, remote attacker, using malformed
packets, can exploit this to cause a device reload.

Note this only affects devices that have configured Media Monitoring
(MMON) or Network-Based Application Recognition (NBAR).");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30ea0b29");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCua79665");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Bug and CVRF
if (version == "3.7.0S") flag++;
if (version == "3.8.0S") flag++;

# CVRF
if (version == "3.6.0S") flag++;
if (version == "3.6.1S") flag++;
if (version == "3.6.2S") flag++;
if (version == "3.7.1S") flag++;
if (version == "3.7.2S") flag++;
if (version == "3.7.3S") flag++;
if (version == "3.7.4S") flag++;
if (version == "3.7.5S") flag++;

# Check configs
if (flag > 0)
{
  flag = 0;

  # Check NBAR
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^\s+ip nbar classification tunneled-traffic (ipv6inip|teredo)", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

  # Check MMON
  buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map-type-perf-mon", "show policy-map type performance-monitor");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^Service-policy performance-monitor (input|output): mmon_policy", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCua79665' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
