#TRUSTED 0ed8bb083d4b7e88c893dd5aeebac1cae810316201fb1bfa9a67c9727921f534a67b9e45948f45991b268ddae87e2f0f1b2f0b60e2b3cfae4c657df04708902ee4260f143bb237d1c2b193434b85d59eee72b65bf4679ca4985ef21d78ad47c929f76331b23e51f6f39791bb7462cf349f7f45078cb0e46faf68336008418d3ad1bc645d3c93b9d66132d43ecc239f56941ac2f8abb868b2900d699b8cb9cd7ec7788242cb348a3f2ae53f66a1086dd7b2495d3f9bfc6dd507ded5d86e86abe4e7d16e4be52d6ac8c241da4e1528c9e27ef0039083135c750c8f0b4ec8aeb67e60bbc41e3e524d98afe96cf38533c88302a1783207d3826f38248eb3a959e489fd96ab98dc14391297899a005454484d6513d08905fa09c567aec5ef261cec521d54334732fad4d7ddbe52cf1603ba990225ecd74e72ca40048d3d3d55f6ea154ee13e36ad2056774354f1bbf3c586406730bdafd1ad656a9ccbf9cfcb35ec181d22455901f88953bd25674cdc32241e0930ee05fe57d2a74b038ebc6377c53fd049f2fa686633aacf00689286ca23cef82d37db7a96f5f226f425e3dc8b1317e94819655ed715f3d5892942ca922281c459e00a5b628c5b0a126de13debf055320ce20c812316f6225b746dfcf652d518039bf49fbd2ae01c6ced13c5d95885ab1c312968dd08b628c5637314b7e154e64306885f00b81267e7d529093fe803
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-ike.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70317);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-5473");
  script_bugtraq_id(62643);
  script_osvdb_id(97736);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx66011");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ike");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Memory Leak Vulnerability (cisco-sa-20130925-ike)");
  script_summary(english:"Checks the IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Internet Key Exchange (IKE) protocol of Cisco
IOS XE Software could allow an unauthenticated, remote attacker to cause
a memory leak that could lead to a device reload.  The vulnerability is
due to incorrect handling of malformed IKE packets by the affected
software.  An attacker could exploit this vulnerability by sending
crafted IKE packets to a device configured with features that leverage
IKE version 1 (IKEv1).  Although IKEv1 is automatically enabled on a
Cisco IOS XE Software when IKEv1 or IKE version 2 (IKEv2) is configured,
the vulnerability can be triggered only by sending a malformed IKEv1
packet.  In specific conditions, normal IKEv1 packets can also cause an
affected release of Cisco IOS XE Software to leak memory.  Only IKEv1 is
affected by this vulnerability.  An exploit could cause Cisco IOS XE
Software not to release allocated memory, causing a memory leak.  A
sustained attack may result in a device reload.  Cisco has released free
software updates that address this vulnerability.  There are no
workarounds to mitigate this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5c40d83");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-ike."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if ( version == '3.4.2S' ) flag++;
if ( version == '3.4.3S' ) flag++;
if ( version == '3.4.4S' ) flag++;
if ( version == '3.4.5S' ) flag++;
if ( version == '3.6S' ) flag++;
if ( version == '3.6.0S' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"crypto gdoi enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"crypto map", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"tunnel protection ipsec", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
