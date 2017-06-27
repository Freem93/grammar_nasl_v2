#TRUSTED 43d6fce661995f8a19dfff1b8a40df500c5b351d0172e8739ec56a0f325de0dce5338272878f3ec8a6faf87c227bf104151e20f510ea3cb856ece1fc18db9d575b73ab10b6e88943218a624793b6b3283139d8126bd1554a2b3d00d807de08b9f1a45350ed408fd938a405e745598022bda2daeecd2ec059953dda0ddc15bb5cba410ddf37496e3b80bb48c6b95fcd38c8299d966eef5bafaa7ab544d7afa2407e2021b6a684c46858657a40adc02b9f8060c0f7d7a0a95bf5308cfd8a4c1794bd6399a8e055f7762be8d9133d5c803f9aeadc881e705decc229e01e8b3df49773edc1620035923ce0a16b868c9665a832a45bf194f0835bb935c6bea5761a0f4ff4bed50a3cb9ba6a87641dc888001021221a49aa590bf1bd30f1c833f502fb0c78261ae726c9b272639f45e1a1a7184c0d7073982733f82afc721bfb692128e670521483b038c39edce9648c9f19a72bed26c52ff439f4bc39ad12104dc2bb97886382c1cf10d4890b08f0a17bc8a20870dd618889cc26a6a8f49ad7a20da5311e1a8b164f7f0f6ee301202e239c017d838e4ad39bba0ec6ec37c0509b1c4f8e92fec0b036ae59d76bbb8bb0128be9a3acab7f36c62782b63ac30ea25f40bbdfd7c0104dcc70e8c2c7943bc843c17ccdcca62ec1c1ad27a89c6cb959ced368130c7d82acd58db34fcccc70218b7efa57f70f0144a84b279ed168b839f9fa21
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a0157a.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49021);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2008-3813");
 script_bugtraq_id(31358);
 script_osvdb_id(48733);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh48879");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-l2tp");
script_name(english:"Cisco IOS Software Layer 2 Tunneling Protocol (L2TP) Denial of Service Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A vulnerability exists in the Cisco IOS software implementation of
Layer 2 Tunneling Protocol (L2TP), which affects limited Cisco IOS
software releases.
Several features enable the L2TP mgmt daemon process within Cisco IOS
software, including but not limited to Layer 2 virtual private networks
(L2VPN), Layer 2 Tunnel Protocol Version 3 (L2TPv3), Stack Group
Bidding Protocol (SGBP) and Cisco Virtual Private Dial-Up Networks
(VPDN). Once this process is enabled the device is vulnerable.
This vulnerability will result in a reload of the device when
processing a specially crafted L2TP packet.
Cisco has released free software updates that address this
vulnerability.
Workarounds that mitigate this vulnerability are available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?022d1ac3");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a0157a.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c0738c28");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-l2tp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

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

if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(37)SG1') flag++;
else if (version == '12.2(40)SE') flag++;
else if (version == '12.2(37)SE1') flag++;
else if (version == '12.2(37)SE') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\sL2TP\s", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
