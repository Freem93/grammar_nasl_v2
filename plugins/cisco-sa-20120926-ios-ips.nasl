#TRUSTED 2888fb667d935621f732c15835d1c5465cf90e5376f69b1f22fc6be915242afbd1bc406e8471e193bcaf9185854bccf348cbfd3e219171e0233057a9a5be9b7814b8c747c1b2b8cdf34128b04257d789690fb68315b17255ef941664e5b4035e788b77833609b75d1670e8c9f90940efe2c627d4e8af72e8bac8f99dbf1c2f5c0a3a49baaab0abc3f0b84ac8ce42e1fd96ac6bfc706a51121ef6007988248bdfa790ee4712023b79fb6d496e207b3ef35896d123cfc38315c8be425828a1629714aa2a0779c79b737a116d79e1e4a56ae583fc39e0479fbe6f6ff9a9b2ea12f7d394315e262a236822651035c8f5316d2efb4618fcf7504c1f032857bc4528319312da100876726bcf4d520bc36e022b7d2d1bde35b7128b08c18bd78757f9d8f53ee6b1bc397f6510852c71fb285b939c3be4ae6703978903f60e0446340ef0a3defb0de739bfb81701af6c4f30c6251ad715e7fdcc88ab0c14580fac7d45acadfe6261917fbf5346c1c999389954a7854460fe88086189f3b0913f5314c7238095682c5e1895ba832435b91be10306f339c61c351d946c9df7c386ddcdfc1a5fe023cb17202536565122a058a4d50850f1c617b021e66faf927848b4bdf437ab78044c7d5d2039a57b379a05938ee08762fe913f029c2afd4b06a0a4875f3bd25adb46cd6cb09dcc490e7758566df4d1e3b7a6c4f3e49bd70806d97e266f9f
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-ios-ips.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62374);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/01/31");

  script_cve_id("CVE-2012-3950");
  script_bugtraq_id(55695);
  script_osvdb_id(85815);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtw55976");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-ios-ips");

  script_name(english:"Cisco IOS Software Intrusion Prevention System Denial of Service Vulnerability (cisco-sa-20120926-ios-ips)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the Intrusion
Prevention System (IPS) feature that could allow an unauthenticated,
remote attacker to cause a reload of an affected device if specific
Cisco IOS IPS configurations exist. Cisco has released free software
updates that address this vulnerability. Workarounds that mitigate
this vulnerability are available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-ios-ips
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0fa6c6d7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-ios-ips."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if ( version == '12.4(11)T' ) flag++;
if ( version == '12.4(11)T1' ) flag++;
if ( version == '12.4(11)T2' ) flag++;
if ( version == '12.4(11)T3' ) flag++;
if ( version == '12.4(11)T4' ) flag++;
if ( version == '12.4(11)XJ' ) flag++;
if ( version == '12.4(11)XJ1' ) flag++;
if ( version == '12.4(11)XJ2' ) flag++;
if ( version == '12.4(11)XJ3' ) flag++;
if ( version == '12.4(11)XJ4' ) flag++;
if ( version == '12.4(11)XJ5' ) flag++;
if ( version == '12.4(11)XJ6' ) flag++;
if ( version == '12.4(11)XV' ) flag++;
if ( version == '12.4(11)XV1' ) flag++;
if ( version == '12.4(11)XW' ) flag++;
if ( version == '12.4(11)XW1' ) flag++;
if ( version == '12.4(11)XW10' ) flag++;
if ( version == '12.4(11)XW2' ) flag++;
if ( version == '12.4(11)XW3' ) flag++;
if ( version == '12.4(11)XW4' ) flag++;
if ( version == '12.4(11)XW5' ) flag++;
if ( version == '12.4(11)XW6' ) flag++;
if ( version == '12.4(11)XW7' ) flag++;
if ( version == '12.4(11)XW8' ) flag++;
if ( version == '12.4(11)XW9' ) flag++;
if ( version == '12.4(14)XK' ) flag++;
if ( version == '12.4(15)T' ) flag++;
if ( version == '12.4(15)T1' ) flag++;
if ( version == '12.4(15)T10' ) flag++;
if ( version == '12.4(15)T11' ) flag++;
if ( version == '12.4(15)T12' ) flag++;
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(15)T13b' ) flag++;
if ( version == '12.4(15)T14' ) flag++;
if ( version == '12.4(15)T15' ) flag++;
if ( version == '12.4(15)T16' ) flag++;
if ( version == '12.4(15)T17' ) flag++;
if ( version == '12.4(15)T2' ) flag++;
if ( version == '12.4(15)T3' ) flag++;
if ( version == '12.4(15)T4' ) flag++;
if ( version == '12.4(15)T5' ) flag++;
if ( version == '12.4(15)T6' ) flag++;
if ( version == '12.4(15)T6a' ) flag++;
if ( version == '12.4(15)T7' ) flag++;
if ( version == '12.4(15)T8' ) flag++;
if ( version == '12.4(15)T9' ) flag++;
if ( version == '12.4(15)XF' ) flag++;
if ( version == '12.4(15)XY' ) flag++;
if ( version == '12.4(15)XY1' ) flag++;
if ( version == '12.4(15)XY2' ) flag++;
if ( version == '12.4(15)XY3' ) flag++;
if ( version == '12.4(15)XY4' ) flag++;
if ( version == '12.4(15)XY5' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)MR1' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)T4' ) flag++;
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(20)T6' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)GC1a' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)T4' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YB6' ) flag++;
if ( version == '12.4(22)YB7' ) flag++;
if ( version == '12.4(22)YB8' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '12.4(24)T7' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)M8' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ips_signatures", "show ip ips signatures");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:".*6054:0\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }

      m = eregmatch(pattern:".*6054:1\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }

      m = eregmatch(pattern:".*6062:0\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }

      m = eregmatch(pattern:".*6062:0\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show ip ips configuration", "show ip ips configuration");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:"Category[ ]*configurations diag2:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*os general_os:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*attack general_attack:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*other_services general_service:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*l2/l3/l4_protocol/ip tcp:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*l2/l3/l4_protocol/ip udp:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*network_services dns:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*ios_ips basic:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*ios_ips advanced:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
