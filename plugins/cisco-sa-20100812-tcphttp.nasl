#TRUSTED 46e0757551354bcc453df2cbddfc87c571a2c205bad23757316c1f1a292c112ced97e657b774eac39baa028392d56d3b6a81665625d6fa4f4aa7dafdb5f87c9ea387eb175fd77df344f60364c1c953140966cc3acac27e7ef7bdff3ea03b0c5ce4917d9ce3a32c185c24868bbe0f9c4b328ebe08b6b76ec5007ca56da1cddb59df1631a0b6dd3544b21b8b61515808bf8eaef966cd9c16d238526d44f598447b35a1fedffd194d7822effe942d009d9f807ae0181c8939de9c3fc2194597af4dd062ad71f3ebde6e9a3b7b8738cc466304c449e92c0e940715faba2cf5661aed4fb30090dc7f161d43aa8c4d4d27667598b6f0a9b6013f11f5ef1bf901069c1cc7c643e9d84d25edf5b36419961b25ab273a8bf92ac8753be0d4c1f2b98aa1d1b84c863beec0c93b676c6728db15449d8bd971e7364b427091ebd64df72b1785ce8c4d5df45c3be67f827150312ad0e6dc5c585df392ef8e847b525a0c05915d585b0ab2b7c8362e89e85131a86730c355e381f81139eeb374ff0008491a2313739c3f0d77f039b4ba1fabf4a29f5e1c40ce91cdc0601cbdb6304b1a7dba009842e1d6b83cb78b3c73558f583207f600ba4426208ddd8e4db2da59f9aeb9da25d54e440be9fdc3d9e56126319ccdcdb486af4fbd3f3ef27d1c123ca01630b2bc14d464a738ae4e177dc26c6de6e7772d28c1488bbe4f6622ede78636196af894
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080b4095e.shtml

include("compat.inc");

if (description)
{
 script_id(49056);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/12");

 script_cve_id("CVE-2010-2827");
 script_bugtraq_id(42426);
 script_osvdb_id(67099);
 script_xref(name:"CISCO-BUG-ID", value:"CSCti18193");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20100812-tcp");

 script_name(english:"Cisco IOS Software TCP Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
"Cisco IOS Software Release, 15.1(2)T is affected by a denial of
service (DoS) vulnerability during the TCP establishment phase. The
vulnerability could cause embryonic TCP connections to remain in a
SYNRCVD or SYNSENT state. Enough embryonic TCP connections in these
states could consume system resources and prevent an affected device
from accepting or initiating new TCP connections, including any
TCP-based remote management access to the device. No authentication is
required to exploit this vulnerability. An attacker does not need to
complete a three-way handshake to trigger this vulnerability;
therefore, this vulnerability can be exploited using spoofed packets.
This vulnerability may be triggered by normal network traffic. Cisco
has released Cisco IOS Software Release 15.1(2)T0a to address this
vulnerability.");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100812-tcp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f433a13e");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080b4095e.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?322225c0");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100812-tcp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");

 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Affected: 15.1T
# Releases prior to 15.1(2)T are not vulnerable.
if (check_release(version: version,
                  patched: make_list("15.1(2)T0a", "15.1(2)T1"),
                  oldest:"15.1(2)T")) { flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SYNRCVD", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"SYNSENT", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/debug_ip_tcp_transactions", "debug ip tcp transactions");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"connection queue limit reached\s+:port", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"No wild listener:\s+port", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
