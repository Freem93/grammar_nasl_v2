#TRUSTED 3f4bedf8817974253ab293254625c77daa64eb295c8c6417e8df630c91ab71a61d5391aa968218126f6bbe11c91a4f227763fb774d21a68653d55e808339c5d1a36e26ac581c9653c25bb8e50a917aac1e35e884590f1edeb81e76f822aa0a5ee722b31b3eab39f06290c4ff3fe630236cfe1a2d5bf6b9c935843c44a3f80c0a3e138b8f397faa83b5579554964b67793012c7572eefd8f04ef0b0795f244b56d1d7681cf0340fdcfc4a67460479d67f8610810cbfd2e7f7a05ff82b4ce25b806cb2ed32a52475b565a272a6c4725eadf74d72db3d52a98c125cf474af38d08ae73e1552cfa0d40029dc15fcefa1773b8a92bbfefce4f9ed52ecb9a15a072491df76f553298520b403dc960ceffb968e09420689344c96a47d66fcad772ffd60df14153816223e1faaf9439d939a5b6a3fef25d1fb42244d083b757e861d60c898277819f7274501edbd28843371e133a754c8f3f55c74e6b6c17e344338667fff746a6887f5e35e6c916830a3cb56c223ccf04da30874c4a834ca3c6911f42434c70ae60ce52c5d88a13f06b045f47d65116c98aad5248c103eef005dbcfe1bf041a0c3e41de9f17167ecee295d904986b3c139e1f09824a0b22341c5212646a524209e2a06824c9f99e65c27f9480b85b68d7736cf1937ae9d09655e6e7f22fa92460180b888dbfdb9929f959e2188976bafdcf6f9b52bfa945b05852b37be
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a014b1.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49027);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2008-3807");
 script_bugtraq_id(31355);
 script_osvdb_id(48739);
 script_xref(name:"CISCO-BUG-ID", value:"CSCek57932");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-ubr");
 script_xref(name:"IAVA", value:"2008-A-0067");
 script_name(english:"Cisco uBR10012 Series Devices SNMP Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco uBR10012 series devices automatically enable Simple Network
Management Protocol (SNMP) read/write access to the device if
configured for linecard redundancy. This can be exploited by an
attacker to gain complete control of the device. Only Cisco uBR10012
series devices that are configured for linecard redundancy are
affected.

 Cisco has released free software updates that address this
vulnerability. Workarounds that mitigate this vulnerability are
available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7be0b39b");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a014b1.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?7c4809ae");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-ubr.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.3(17b)BC7') flag++;
else if (version == '12.3(17b)BC6') flag++;
else if (version == '12.3(17b)BC5') flag++;
else if (version == '12.3(17b)BC4') flag++;
else if (version == '12.3(17b)BC3') flag++;
else if (version == '12.3(17a)BC2') flag++;
else if (version == '12.3(17a)BC1') flag++;
else if (version == '12.3(17a)BC') flag++;
else if (version == '12.3(13a)BC6') flag++;
else if (version == '12.3(13a)BC5') flag++;
else if (version == '12.3(13a)BC4') flag++;
else if (version == '12.3(13a)BC3') flag++;
else if (version == '12.3(13a)BC2') flag++;
else if (version == '12.3(13a)BC1') flag++;
else if (version == '12.3(13a)BC') flag++;
else if (version == '12.3(9a)BC9') flag++;
else if (version == '12.3(9a)BC8') flag++;
else if (version == '12.3(9a)BC7') flag++;
else if (version == '12.3(9a)BC6') flag++;
else if (version == '12.3(9a)BC5') flag++;
else if (version == '12.3(9a)BC4') flag++;
else if (version == '12.3(9a)BC3') flag++;
else if (version == '12.3(9a)BC2') flag++;
else if (version == '12.3(9a)BC1') flag++;
else if (version == '12.3(9a)BC') flag++;
else if (version == '12.2(4)XF1') flag++;
else if (version == '12.2(4)XF') flag++;
else if (version == '12.2(11)CY') flag++;
else if (version == '12.2(15)CX1') flag++;
else if (version == '12.2(15)CX') flag++;
else if (version == '12.2(11)CX') flag++;
else if (version == '12.2(15)BC2i') flag++;
else if (version == '12.2(15)BC2h') flag++;
else if (version == '12.2(15)BC2g') flag++;
else if (version == '12.2(15)BC2f') flag++;
else if (version == '12.2(15)BC2e') flag++;
else if (version == '12.2(15)BC2d') flag++;
else if (version == '12.2(15)BC2c') flag++;
else if (version == '12.2(15)BC2b') flag++;
else if (version == '12.2(15)BC2a') flag++;
else if (version == '12.2(15)BC2') flag++;
else if (version == '12.2(15)BC1g') flag++;
else if (version == '12.2(15)BC1f') flag++;
else if (version == '12.2(15)BC1e') flag++;
else if (version == '12.2(15)BC1d') flag++;
else if (version == '12.2(15)BC1c') flag++;
else if (version == '12.2(15)BC1b') flag++;
else if (version == '12.2(15)BC1a') flag++;
else if (version == '12.2(15)BC1') flag++;
else if (version == '12.2(11)BC3d') flag++;
else if (version == '12.2(11)BC3c') flag++;
else if (version == '12.2(11)BC3b') flag++;
else if (version == '12.2(11)BC3a') flag++;
else if (version == '12.2(11)BC3') flag++;
else if (version == '12.2(11)BC2a') flag++;
else if (version == '12.2(11)BC2') flag++;
else if (version == '12.2(11)BC1b') flag++;
else if (version == '12.2(11)BC1a') flag++;
else if (version == '12.2(11)BC1') flag++;
else if (version == '12.2(8)BC2a') flag++;
else if (version == '12.2(8)BC2') flag++;
else if (version == '12.2(8)BC1') flag++;
else if (version == '12.2(4)BC1b') flag++;
else if (version == '12.2(4)BC1a') flag++;
else if (version == '12.2(4)BC1') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"member subslot [^\r\n]+ working", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"hccp [^\r\n]+ protect ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
