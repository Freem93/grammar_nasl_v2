#TRUSTED 6bb43ef2b78738161e47447027eeec11cf6ec9c3e309a42048f983f5a7e7a75f73d78acc03225e3fb66490d151d30ea9930022d5684a3948c5ce46f3f7798499f867c5fcb003bb65614c8c6bc85785dec0b0311dcc81bc9a83daea1772395adec8896fc75e2086ec050cb3b8f010d57d2eb61620b393ee99089a86ba3422392f189792d24ab67568a43a0c3e83f633cdd0093db80780b4a7e80ae2084c0c8d570d5c6815c0a35311ff0e88d084320c35e80b826273a6e03aac29ad7e68552e929aaf184ff246fc4ad403d4d9d5e4e658607350e01e75cc2f57b60e686a5c44939afb1a41ce3bbdc4bbe9e22c4906ae7c78b0bc28cbeb31570f9f309ef545a872848a12fcc66fd241fab323d63e853cbb53c9ad66c5ecb42a31e07b0f508d90519976c35900dc60757655a1b93aced6716ad7459f1eff58d28c922b9c1aa5eba09b3e379a793e05ce4a3f25b63553e4fc1beaab3028a12a1857efce4616cc3ed6ba81a2c8c0050ed14c19891cb144ad53f973d72deeb55c2710e4b2f1f20c399c0bb76778246bfe0aa4506da9b1d075890f21a45471839c3de0ca606b0a6c262251fab0b251793b3eaabe73fc139c1678cd5335eb8bed3edf310a003994fcdb2cb95dcfc742cdd4641b9dcf6efd478773dcc68dc65de2356df2d976bca47ed92333008b16b4cc9bc47d2014ca41c2aede3dfcda0e5cf658a25e0416d3bde814ea
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080969882.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49014);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2008-0537");
 script_bugtraq_id(28463);
 script_osvdb_id(43789);
 script_name(english:"Vulnerability in Cisco IOS with OSPF, MPLS VPN, and Supervisor 32, Supervisor 720, or Route Switch Processor 720");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Certain Cisco Catalyst 6500 Series and Cisco 7600 Router devices that
run branches of Cisco IOS based on 12.2 can be vulnerable to a denial
of service vulnerability that can prevent any traffic from entering an
affected interface. For a device to be vulnerable, it must be
configured for Open Shortest Path First (OSPF) Sham-Link and Multi
Protocol Label Switching (MPLS) Virtual Private Networking (VPN). This
vulnerability only affects Cisco Catalyst 6500 Series or Catalyst 7600
Series devices with the Supervisor Engine 32 (Sup32), Supervisor Engine
720 (Sup720) or Route Switch Processor 720 (RSP720) modules. The
Supervisor 32, Supervisor 720, Supervisor 720-3B, Supervisor 720-3BXL,
Route Switch Processor 720, Route Switch Processor 720-3C, and Route
Switch Processor 720-3CXL are all potentially vulnerable.
 OSPF and MPLS VPNs are not enabled by default.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06bb02a0");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080969882.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ec51952c");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080326-queue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/26");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsf12082");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080326-queue");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.2(18)ZU2') flag++;
else if (version == '12.2(18)ZU1') flag++;
else if (version == '12.2(18)ZU') flag++;
else if (version == '12.2(18)SXF5') flag++;
else if (version == '12.2(18)SXF4') flag++;
else if (version == '12.2(18)SXF3') flag++;
else if (version == '12.2(18)SXF2') flag++;
else if (version == '12.2(18)SXF1') flag++;
else if (version == '12.2(18)SXF') flag++;
else if (version == '12.2(18)SXE6b') flag++;
else if (version == '12.2(18)SXE6a') flag++;
else if (version == '12.2(18)SXE6') flag++;
else if (version == '12.2(18)SXE5') flag++;
else if (version == '12.2(18)SXE4') flag++;
else if (version == '12.2(18)SXE3') flag++;
else if (version == '12.2(18)SXE2') flag++;
else if (version == '12.2(18)SXE1') flag++;
else if (version == '12.2(18)SXE') flag++;
else if (version == '12.2(18)SXD7b') flag++;
else if (version == '12.2(18)SXD7a') flag++;
else if (version == '12.2(18)SXD7') flag++;
else if (version == '12.2(18)SXD6') flag++;
else if (version == '12.2(18)SXD5') flag++;
else if (version == '12.2(18)SXD4') flag++;
else if (version == '12.2(18)SXD3') flag++;
else if (version == '12.2(18)SXD2') flag++;
else if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(18)SXD') flag++;
else if (version == '12.2(17d)SXB9') flag++;
else if (version == '12.2(17d)SXB8') flag++;
else if (version == '12.2(17d)SXB7') flag++;
else if (version == '12.2(17d)SXB6') flag++;
else if (version == '12.2(17d)SXB5') flag++;
else if (version == '12.2(17d)SXB4') flag++;
else if (version == '12.2(17d)SXB3') flag++;
else if (version == '12.2(17d)SXB2') flag++;
else if (version == '12.2(17d)SXB11a') flag++;
else if (version == '12.2(17d)SXB11') flag++;
else if (version == '12.2(17d)SXB10') flag++;
else if (version == '12.2(17d)SXB1') flag++;
else if (version == '12.2(17d)SXB') flag++;
else if (version == '12.2(17b)SXA2') flag++;
else if (version == '12.2(17b)SXA') flag++;
else if (version == '12.2(33)SRA3') flag++;
else if (version == '12.2(33)SRA2') flag++;
else if (version == '12.2(33)SRA1') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(18)IXE') flag++;
else if (version == '12.2(18)IXD1') flag++;
else if (version == '12.2(18)IXD') flag++;
else if (version == '12.2(18)IXC') flag++;
else if (version == '12.2(18)IXB2') flag++;
else if (version == '12.2(18)IXB1') flag++;
else if (version == '12.2(18)IXB') flag++;
else if (version == '12.2(18)IXA') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"sham-link", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"address-family vpnv4", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
