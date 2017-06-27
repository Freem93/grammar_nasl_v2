#TRUSTED 339fae8932861169f93af81f4e7de55c0de310d14125e7eb7cc58d3cc8ff6db9e5c75e8be7e172b08313ddc60beddb87b230cb0d82b4f79b457e9d5383d3095fdae78baf04fab4a6f50b194861da58b456c1413596a9393e2c1e840c67115a46be4e7147475eb2d6db31e17140878357a68f09913cb973207d8e83b690c4cea69b41074381fe63828a7bcf55ef10df730d6d8c7edb8e581b42399a01311e10a8b986e25a69c55044dea4b74173b2c77a30988de2207be76d0990e4ad4a5a97bf8e014982af0578c29cd914c9228120847d3cbe254bb136fc9876fb9867935e81201490e4f7af96dd0ad97ef14f4411e9d7ce7dc621d970747eb24fce737d41bd99e71c9d41045f25a75a21dfbf0d164a94ac613c50aa0706083ec6d8d381e7e1a8cd0e7c8a8519c2f7d0868c092059a50ab2738833d4707e2ffa9dc4773220e89d20921afeee9a91eb27341012987abcaed7cd00e738ac328e28ec8c1831d4e1e80ef9834cefbb88099a4c2151cdfe91790862610862e260465ab5b2e76b008a9e2ede1e21f877df7c55a2327255c0c016e5e64d593a1b3bb93da04a0354b9a2a0697718726ec120934763f2423ffde2b3459010347a6187651290044b3a651e89f3f789ad1d63fdc5f7bf4b44444e8994e8f524970999a4efbfb90943b75268d8631268242aee894d6cfc71584894e70ce066718fb24523c533aa2f0bebced1
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008021b9b5.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48974);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2004-0714");
 script_bugtraq_id(10186);
 script_osvdb_id(5575);
 script_xref(name:"CERT", value:"162451");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeb22276");
 script_xref(name:"CISCO-BUG-ID", value:"CSCed68575");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040420-snmp");
 script_name(english:"Vulnerabilities in SNMP Message Processing - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco Internetwork Operating System (IOS) Software release trains
12.0S, 12.1E, 12.2, 12.2S, 12.3, 12.3B and 12.3T may contain a
vulnerability in processing SNMP requests which, if exploited, could
cause the device to reload.
 The vulnerability is only present in certain IOS releases on Cisco
routers and switches. This behavior was introduced via a code change
and is resolved with CSCed68575.
 This vulnerability can be remotely triggered. A successful
exploitation of this vulnerability may cause a reload of the device and
could be exploited repeatedly to produce a denial of service (DoS).
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9235a09c");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a008021b9b5.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?40eebe65");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040420-snmp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/04/20");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC1') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2a') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.3(5a)B') flag++;
else if (version == '12.3(6)') flag++;
else if (version == '12.3(5b)') flag++;
else if (version == '12.3(5a)') flag++;
else if (version == '12.3(5)') flag++;
else if (version == '12.2(23)SW1') flag++;
else if (version == '12.2(23)SW') flag++;
else if (version == '12.2(21)SW1') flag++;
else if (version == '12.2(21)SW') flag++;
else if (version == '12.2(20)SW') flag++;
else if (version == '12.2(20)S1') flag++;
else if (version == '12.2(20)S') flag++;
else if (version == '12.2(12h)M1') flag++;
else if (version == '12.2(23)') flag++;
else if (version == '12.2(21a)') flag++;
else if (version == '12.2(21)') flag++;
else if (version == '12.2(12h)') flag++;
else if (version == '12.2(12g)') flag++;
else if (version == '12.1(20)EW1') flag++;
else if (version == '12.1(20)EW') flag++;
else if (version == '12.1(20)EU') flag++;
else if (version == '12.1(20)EO') flag++;
else if (version == '12.1(20)EC1') flag++;
else if (version == '12.1(20)EC') flag++;
else if (version == '12.1(20)EB') flag++;
else if (version == '12.1(20)EA1') flag++;
else if (version == '12.1(20)E2') flag++;
else if (version == '12.1(20)E1') flag++;
else if (version == '12.1(20)E') flag++;
else if (version == '12.0(27)S') flag++;
else if (version == '12.0(26)S1') flag++;
else if (version == '12.0(24)S5') flag++;
else if (version == '12.0(24)S4a') flag++;
else if (version == '12.0(24)S4') flag++;
else if (version == '12.0(23)S5') flag++;
else if (version == '12.0(23)S4') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"snmp-server\s+enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
