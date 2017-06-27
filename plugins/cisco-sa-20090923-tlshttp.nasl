#TRUSTED 04d2e181b1a515eaaccca7f7c6504d04336195eb1b8b775c46da9f187500abe2210b40a6f9034282174f80738f6467e70069c195255ea7ed357b0e3e6421ea85d9ee94f8923c7d2692780f121893b61df3e426f03ebc4b742922e897f0f31321eea6e604391ffc193b8f454eb663825b472d4f3dfd489334c1d816c3c89d16c2cd36f1636b0b8f9b0cf83cc2e31e7417e58c0aea19cebb9aacf2f7795db86d6a5eca558459e3daa47c9deeed7631e672ad513bcf7d05e1fb2338190a852d4c11f56d4319b0b1f702fb1009a604e919fab16386c0392ff5376a7c62de48a278fb09ca7ef0585fde8249a51f23d7f8917293dd55c981729391a52f05ae1240f604e9b1ba71e20f0de52a1819dbb1aedf1654676b201999bf3200aa88d7832c8a065dbf8effaf6d5a982d5595aa4cc947bde2d4378125f9b4b04674d10092dfc87b2cb4adf6bc7fc961a18a0754d7b8f5a9776de899320b5999b18fc83fd82b113277a286e566198f6d55882a588cb1393defd0d1aa41c1cb45bd974df008618cdf207203949fcd56f7b71b2dcb8dcc94c6de0088504d499244e1e54f370afff7d0a8a1b8d2bd03a1f73b66da7ba8ceaf7965c7219c8916cc95affc8139965c517b5d2f64e3ba7d906c9b7b1c24ba2809e4fafe83d6eed4b99efa9987aee273a2dfbf90dbd47c1cbf2993e3d7a12e1247632457b68ee6469a1724882195fb1cb7c8
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af811c.shtml

include("compat.inc");

if (description)
{
 script_id(49047);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2009-2871");
 script_bugtraq_id(36493);
 script_osvdb_id(58339);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsq24002");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-tls");

 script_name(english:"Cisco IOS Software Crafted Encryption Packet Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS Software contains a vulnerability that could allow an
attacker to cause a Cisco IOS device to reload by remotely sending a
crafted encryption packet.

 Cisco has released free software updates that address this
vulnerability.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08f7f949");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af811c.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?824f7ad1");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-tls.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
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

if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY5') flag++;
else if (version == '12.4(15)XY4') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW9') flag++;
else if (version == '12.4(11)XW8') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW10') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(15)XR4') flag++;
else if (version == '12.4(15)XR3') flag++;
else if (version == '12.4(15)XR2') flag++;
else if (version == '12.4(15)XR1') flag++;
else if (version == '12.4(15)XR') flag++;
else if (version == '12.4(15)XQ2') flag++;
else if (version == '12.4(15)XQ1') flag++;
else if (version == '12.4(15)XQ') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(20)T2') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(15)T9') flag++;
else if (version == '12.4(15)T8') flag++;
else if (version == '12.4(15)T7') flag++;
else if (version == '12.4(15)T6') flag++;
else if (version == '12.4(15)T5') flag++;
else if (version == '12.4(15)T4') flag++;
else if (version == '12.4(15)T3') flag++;
else if (version == '12.4(15)T2') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(15)SW3') flag++;
else if (version == '12.4(15)SW2') flag++;
else if (version == '12.4(15)SW1') flag++;
else if (version == '12.4(15)SW') flag++;
else if (version == '12.4(11)SW3') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(19)MR2') flag++;
else if (version == '12.4(19)MR1') flag++;
else if (version == '12.4(19)MR') flag++;
else if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(15)MD2') flag++;
else if (version == '12.4(15)MD1') flag++;
else if (version == '12.4(15)MD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"webvpn enable", multiline:TRUE, string:buf)) && (preg(pattern:"ssl trustpoint", multiline:TRUE, string:buf)) && (preg(pattern:"webvpn Gateway", multiline:TRUE, string:buf)) ) { flag = 1; }
      if (preg(pattern:"authentication rsa-encr", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SSH Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
