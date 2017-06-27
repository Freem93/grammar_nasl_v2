#TRUSTED 91d9b9d896ec743e11e21ce346af168647230a0bc1f802c96ca47e98caee095f04962b7b6aa88c6bf735bdcc11bf92de431e12485ad65dc72002149cb20d63730e0e497f6dbea594d4629e06e1f44793e795b05d69eb3dfa5c611d5d1e14327edc86c9890cb49d9bc45a144e864cdcb316eef5e289c9c0db6889d7652e29986d40435615d47cb2c2d8f4b5952b07950e7387473716fed30466074986766d534a91b512ad6d6b76bc94317c2a4f337107e78996f713f876a4767b479d2aae44e2b1c88758ad0619512747ab6da2f4491249ae71ceaaf559b3d8b8597a7ace67e9755907ed8601cd7ba03dc4e6fbe118d15810d837fbc03ff06305bb5e0e580e779599c68913400724ff900118bb14df8cd2c3255da5cd71e006d8d3367a0dc03865efec91a76576b190c5a8cfd7e9fa01d9a369eb0557ad05dd68e764fbaa7f51a888686055f38c8bb4500ee94c170939708f254ea7778fb3df17cdde780fe3012666a7436f4408fa2b2d11cf880bcc901f6be98377a605c1525221e0549e4c3514d0f3ac915d6eb6d6220df1735d63846b3f6146a8c4b124a5d7aa550281a2404ce23eea68a17606cbb2bba847d5a9909fd1e8ee1a434a3b153a0d3c457c260b75ea57152e873f7836a329581d027415b27fb201c60fc3720d04d16b68b4da8a1ba90dcc5f2523eaadce8cf5f2deb36c5e693d9767358266dad3bf80109550fe
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82575);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0642", "CVE-2015-0643");
  script_bugtraq_id(73333);
  script_osvdb_id(119939, 119940);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum36951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo75572");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ikev2");

  script_name(english:"Cisco IOS XE IKEv2 DoS (cisco-sa-20150325-ikev2)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 2 (IKEv2) subsystem
due to improper handling of specially crafted IKEv2 packets. A remote,
unauthenticated attacker can exploit this issue to cause a device
reload or exhaust memory resources.

Note that this issue only affects devices with IKEv1 or ISAKMP
enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f444bf3");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37815");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37816");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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
if (
  version =~ "^2\.[56]([^0-9]|$)" ||
  version =~ "^3\.2(\.[0-9]+)?S([^EGQ]|$)" ||
  version =~ "^3\.([1-9]|11)(\.[0-9]+)?S([^EGQ]|$)" ||
  version =~ "^3\.12(\.[0-2])?S([^EG]|$)"
)
{
  fix = "3.12.3S";
  flag++;
}

if(
  version =~ "^3\.10(\.[0-4])?S([^EG]|$)"
)
{
  fix = "3.10.5S";
  flag++;
}

if (
  version =~ "^3\.13(\.[01])?S([^EG]|$)"
)
{
  fix = "3.13.2S";
  flag++;
}

if (
  version =~ "^3\.6(\.[0-4])?E"
)
{
  fix = "3.6.5E";
  flag++;
}

if (
  version =~ "^3\.2(\.[0-9]+)?SE$" ||
  version =~ "^3\.3(\.[0-9]+)?[SE|SG|XO]" ||
  version =~ "^3\.4(\.[0-9]+)?SG" ||
  version =~ "^3\.5(\.[0-9]+)?E" ||
  version =~ "^3\.7(\.0)?E"
)
{
  fix = "3.7.1E";
  flag++;
}

# Check that IKEv1 or ISAKMP is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";

  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s500\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s848\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s4500\s", string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (fix && flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCum36951 and CSCuo75572' +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
