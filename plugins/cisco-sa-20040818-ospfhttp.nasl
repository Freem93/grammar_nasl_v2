#TRUSTED 95624a114f8f20bb455d9695ab8cf0ef25a42c5edcbcf4726a1f1483d29a3be2ceb472812eb8cb7647580d32aa9ee512820d89116e2e36a2e9f0ef470abcf6b5d775838c8f8751998b3a3a0eab4e823de3f3c3fffff0bb41338f52631433100e750318d3f0733615dba87f294a31ac20e131e8b20f572249bd7e9082b4abbeaf519d9190c02baf22e8909a16565b942a0bbe39bfd1b3a2de1281998f82a5351b7fb9c977652fdb955e464db2e181d34a0fdecdff248ed6efd983ef2b4a53402a613145a0c2b0c3b7015ddcebea0a5928f6a0d8a4e5dc694f920909bb566e7c79a87bb05e0f283d9911555ed2448bacbd49056eace4a019978be4529720252c881ccb9d7a3d024f703e60bcf7112d873b958f639cee4b1fe3d75eb81584be8026b837bccd64557c58f3f9d64e388ab5c6c2586b9e78747a779eb9ae57bfae4f79603596f26bf5a01ef5176dbcfddd48e29ec568bbcbbddae251564b303426bdc26c7a0e82434701a45483fe65ec158ca3a43839441758663c3dc055e06051451f7c8c69aec9550f9e0d2836876b9155bb2a9e5464da48323ec49091d0114a7d15013857a213a4bc6538ed2b8075283711d28e41a2a548ea710d110039df96c9d4c84b1d7e0c3564e4a56f26b3187d8977cb98e3196b59e5d3033501af019460078b844f35071baad7501eccefe8925ecbcde422a54443f3c096bc098059d309bd
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008029e189.shtml

include("compat.inc");

if (description)
{
 script_id(48976);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2004-1454");
 script_osvdb_id(9009);
 script_xref(name:"CISCO-BUG-ID", value:"CSCec16481");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040818-ospf");

 script_name(english:"Cisco IOS Malformed OSPF Packet Causes Reload - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"A Cisco device running Internetwork Operating System (IOS) and
enabled for the Open Shortest Path First (OSPF) protocol is vulnerable
to a denial of service (DoS) attack from a malformed OSPF packet. The
OSPF protocol is not enabled by default.

The vulnerability is only present in Cisco IOS release trains based on
12.0S, 12.2, and 12.3. Releases based on 12.0, 12.1 mainlines, and all
Cisco IOS images prior to 12.0 are not affected.

Cisco has made free software available to address this vulnerability.
There are workarounds available to mitigate the effects.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fefa1e85");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a008029e189.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1e1f15d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040818-ospf.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/08/18");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(2)XE') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC1') flag++;
else if (version == '12.3(2)XC') flag++;
else if (version == '12.3(2)XB1') flag++;
else if (version == '12.3(2)XB') flag++;
else if (version == '12.3(2)XA4') flag++;
else if (version == '12.3(2)XA2') flag++;
else if (version == '12.3(2)XA1') flag++;
else if (version == '12.3(2)XA') flag++;
else if (version == '12.3(2)T3') flag++;
else if (version == '12.3(2)T2') flag++;
else if (version == '12.3(2)T1') flag++;
else if (version == '12.3(2)T') flag++;
else if (version == '12.3(1a)BW') flag++;
else if (version == '12.3(3)B1') flag++;
else if (version == '12.3(3)B') flag++;
else if (version == '12.3(1a)B') flag++;
else if (version == '12.3(3e)') flag++;
else if (version == '12.3(3c)') flag++;
else if (version == '12.3(3b)') flag++;
else if (version == '12.3(3a)') flag++;
else if (version == '12.3(3)') flag++;
else if (version == '12.3(1a)') flag++;
else if (version == '12.3(1)') flag++;
else if (version == '12.2(15)ZL1') flag++;
else if (version == '12.2(15)ZL') flag++;
else if (version == '12.2(15)ZJ5') flag++;
else if (version == '12.2(15)ZJ3') flag++;
else if (version == '12.2(15)ZJ2') flag++;
else if (version == '12.2(15)ZJ1') flag++;
else if (version == '12.2(15)ZJ') flag++;
else if (version == '12.2(13)ZH5') flag++;
else if (version == '12.2(13)ZH3') flag++;
else if (version == '12.2(13)ZH2') flag++;
else if (version == '12.2(13)ZH') flag++;
else if (version == '12.2(13)ZF2') flag++;
else if (version == '12.2(13)ZF1') flag++;
else if (version == '12.2(13)ZF') flag++;
else if (version == '12.2(13)ZE') flag++;
else if (version == '12.2(13)ZD4') flag++;
else if (version == '12.2(13)ZD3') flag++;
else if (version == '12.2(13)ZD2') flag++;
else if (version == '12.2(13)ZD1') flag++;
else if (version == '12.2(13)ZD') flag++;
else if (version == '12.2(11)YV') flag++;
else if (version == '12.2(11)YU') flag++;
else if (version == '12.2(15)T7') flag++;
else if (version == '12.2(15)T5') flag++;
else if (version == '12.2(15)T4e') flag++;
else if (version == '12.2(15)T4') flag++;
else if (version == '12.2(15)T2') flag++;
else if (version == '12.2(15)T1') flag++;
else if (version == '12.2(15)T') flag++;
else if (version == '12.2(14)SZ6') flag++;
else if (version == '12.2(14)SZ5') flag++;
else if (version == '12.2(14)SZ4') flag++;
else if (version == '12.2(14)SZ3') flag++;
else if (version == '12.2(14)SZ2') flag++;
else if (version == '12.2(14)SZ1') flag++;
else if (version == '12.2(14)SZ') flag++;
else if (version == '12.2(19)SW') flag++;
else if (version == '12.2(18)SW') flag++;
else if (version == '12.2(18)SV3') flag++;
else if (version == '12.2(18)SV2') flag++;
else if (version == '12.2(18)SV1') flag++;
else if (version == '12.2(18)SV') flag++;
else if (version == '12.2(18)SE1') flag++;
else if (version == '12.2(18)SE') flag++;
else if (version == '12.2(18)S4') flag++;
else if (version == '12.2(18)S3') flag++;
else if (version == '12.2(18)S2') flag++;
else if (version == '12.2(18)S1') flag++;
else if (version == '12.2(18)S') flag++;
else if (version == '12.2(15)MC2') flag++;
else if (version == '12.2(15)MC1c') flag++;
else if (version == '12.2(15)MC1b') flag++;
else if (version == '12.2(15)MC1a') flag++;
else if (version == '12.2(15)MC1') flag++;
else if (version == '12.2(18)EW') flag++;
else if (version == '12.2(15)CX1') flag++;
else if (version == '12.2(15)CX') flag++;
else if (version == '12.2(15)BZ2') flag++;
else if (version == '12.2(16)BX3') flag++;
else if (version == '12.2(16)BX2') flag++;
else if (version == '12.2(16)BX1') flag++;
else if (version == '12.2(16)BX') flag++;
else if (version == '12.2(15)BX') flag++;
else if (version == '12.2(15)BC1b') flag++;
else if (version == '12.2(15)BC1a') flag++;
else if (version == '12.2(15)BC1') flag++;
else if (version == '12.2(16)B2') flag++;
else if (version == '12.2(16)B1') flag++;
else if (version == '12.2(16)B') flag++;
else if (version == '12.2(15)B') flag++;
else if (version == '12.0(23)SZ3') flag++;
else if (version == '12.0(25)SX1') flag++;
else if (version == '12.0(25)SX') flag++;
else if (version == '12.0(23)SX5') flag++;
else if (version == '12.0(23)SX4') flag++;
else if (version == '12.0(23)SX3') flag++;
else if (version == '12.0(23)SX2') flag++;
else if (version == '12.0(23)SX1') flag++;
else if (version == '12.0(23)SX') flag++;
else if (version == '12.0(26)S') flag++;
else if (version == '12.0(25)S1c') flag++;
else if (version == '12.0(25)S1b') flag++;
else if (version == '12.0(25)S1a') flag++;
else if (version == '12.0(25)S1') flag++;
else if (version == '12.0(25)S') flag++;
else if (version == '12.0(24)S3') flag++;
else if (version == '12.0(24)S2b') flag++;
else if (version == '12.0(24)S2a') flag++;
else if (version == '12.0(24)S2') flag++;
else if (version == '12.0(24)S1') flag++;
else if (version == '12.0(24)S') flag++;
else if (version == '12.0(23)S4') flag++;
else if (version == '12.0(23)S3c') flag++;
else if (version == '12.0(23)S3b') flag++;
else if (version == '12.0(23)S3a') flag++;
else if (version == '12.0(23)S3') flag++;
else if (version == '12.0(23)S2a') flag++;
else if (version == '12.0(23)S2') flag++;
else if (version == '12.0(23)S1') flag++;
else if (version == '12.0(23)S') flag++;
else if (version == '12.0(22)S5a') flag++;
else if (version == '12.0(22)S5') flag++;
else if (version == '12.0(22)S4a') flag++;
else if (version == '12.0(22)S4') flag++;
else if (version == '12.0(22)S3c') flag++;
else if (version == '12.0(22)S3b') flag++;
else if (version == '12.0(22)S3a') flag++;
else if (version == '12.0(22)S3') flag++;
else if (version == '12.0(22)S2e') flag++;
else if (version == '12.0(22)S2d') flag++;
else if (version == '12.0(22)S2c') flag++;
else if (version == '12.0(22)S2b') flag++;
else if (version == '12.0(22)S2a') flag++;
else if (version == '12.0(22)S2') flag++;
else if (version == '12.0(22)S1') flag++;
else if (version == '12.0(22)S') flag++;



if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"router\s+ospf\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
