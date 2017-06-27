#TRUSTED 0fb706fc19dfec88e0ba930a1d4e35a0bd2a1571caa8c7a01c9727d1ffe04d7d5c094e5baa7e44226daa116ecee8e8c6fe498cf67fd3bc8b60ca29af6fc95dcbd6f99acaf385a7b0befb4c86b16bd1aa916f4c38d3d2493229d56460e65f459369f00ffcd476dc0126fe43d5aeec05c71b73563a57d41b6d703865517dab48f7fa828a2ad7f925e449f677f2c2d587a8cd450e8376b829a7d55f4fcb5f305f2ca8e80969fc75ff7c588d533545d63bbdbe3d5d554ee44bccb7ea12498cef028271c833d5c133d6527ea031dbe1aa89f7da5d3cc83a12fdfe43639f02449130e920639baaf17d4d94e155ac386de7e0f7b3339973730ded748b1b895a08d209783265004b6e61fa049cce3f07a29cb7d7729d1d21a0930e4d59be73e77d621cb37c324eaf3ed0d3d61298dd84a6d45b3c9d6b6626d51bcb4802b1fd46d0b8a48c5dc820941632c5401aca6abb6e52e2ce989e006850ed290cda256862eb9fc619e0262d0c4cc9238fcd4d81be67e4807c22463667ea8683684c146fe938f1d46789bdd355861619f329bc6a849629ee0fe0bd3e285cbb50fe3d976c2aaec3cb557d3c4081658943ab842535473a6c9119f0c0ee9e7a28cd6d5b449b20ea1193620fb824897ac04f19e1c71a40d89a7ecd9940a542025226948de3c8443ed4ccd628601176752a8f48f2fb35a8d54c903b232f3cce4f04f5ab3650415b94be347c
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-wedge.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70323);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-5477");
  script_bugtraq_id(62645);
  script_osvdb_id(97733);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub67465");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-wedge");

  script_name(english:"Cisco IOS Software Queue Wedge Denial of Service Vulnerability (cisco-sa-20130925-wedge)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the T1/E1 driver queue implementation of Cisco IOS
Software could allow an unauthenticated, remote attacker to cause an
interface wedge condition, which could lead to loss of connectivity,
loss of routing protocol adjacency, and could result in a denial of
service (DoS) scenario. The vulnerability is due to incorrect
implementation of the T1/E1 driver queue. An attacker could exploit
this vulnerability by sending bursty traffic through the affected
interface driver. Repeated exploitation could cause a DoS condition.
Workarounds to mitigate this vulnerability are available. Cisco has
released free software updates that address this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-wedge
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27ae6075"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-wedge."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M10' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)M8' ) flag++;
if ( version == '15.0(1)M9' ) flag++;
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
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)M6' ) flag++;
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
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(1)T4' ) flag++;
if ( version == '15.2(100)T' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)JA' ) flag++;
if ( version == '15.2(2)JA1' ) flag++;
if ( version == '15.2(2)JAX' ) flag++;
if ( version == '15.2(2)JB' ) flag++;
if ( version == '15.2(2)JB1' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if ( version == '15.2(4)JA' ) flag++;
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if ( version == '15.3(1)T' ) flag++;
if ( version == '15.3(1)T1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_interfaces", "show interfaces");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"address is [1-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,3}\r\n( +.*\r\n){1,3} +[Ee]ncapsulation HDLC", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    if (flag)
    {
      flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_controllers_e1", "show controllers e1");
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"[Ll]ine", multiline:TRUE, string:buf)) { flag = 1; }
        if (preg(pattern:"[Ii]nternal", multiline:TRUE, string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

      buf = cisco_command_kb_item("Host/Cisco/Config/show_controllers_t1", "show controllers t1");
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"[Ll]ine", multiline:TRUE, string:buf)) { flag = 1; }
        if (preg(pattern:"[Ii]nternal", multiline:TRUE, string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
    else { flag = 0; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
