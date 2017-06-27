#TRUSTED 24c8bcb26372199219216d280a6609401fe4cb1a349ee6c74c2f7791539e4f0fcbd249cec13ccb82227d54e865bf37829dca88bb84aa7d77a69cd30054f39d9c74d57785823277b967adf2efd66672329aaf8484cde40bc93c759d3acf186410e0b553e2fe9a2086d3987396a8184fde4cc328d4f09101cd268608d0acf07f975038b8341dd36e1a533ebe3841a41256c1055cea71fd404ffc0c8f424c68ec7905bc81a3bda99fa3d121ec221a592de39fd07afc0b589e5fc37ef1029be213e99c7c1241b97cb8779fae030d82e3059a541db3553564ba14de7918073c5990abb17e0e9f5dc95bc5ea777997608e1ec87737b9903cd9a457e35cfc3bbe4cc88a2c08c7b9b572d87ae4d5c1df26ac2887589769bdce1811edd624ac6b3ec2e0b30d7bae5f253445d3e33aa6706896bf4f47696793d5f67eec9003c88aeabd6c8078b63025083d780b47b031609dc8162823d4a5367f64923b6d3b116be392ae18e086093ec60dba25b713b76db6befc1e3f236d20cf751a4a02e3a6d58eb122622b8a8ac661fbd424954beede108d8b914fb86cc1d7ad4f58b5e0a87567f7b1412aa10c6a7e62e3bc3c5ff226cf6a142fc2f6014f1544a62f5a98c0d2e4269e1288a628118e8b207713ae604fd3ab8d829bef3f50eeb67f43489a9cc1b89348397537ec4cef06ce3f487e01644b3972e4750076483cce11bece454e67bbfaa637
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
  script_id(70318);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-5473");
  script_bugtraq_id(62643);
  script_osvdb_id(97736);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx66011");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ike");

  script_name(english:"Cisco IOS Software Internet Key Exchange Memory Leak Vulnerability (cisco-sa-20130925-ike)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability exists in the Internet Key Exchange (IKE) protocol of
Cisco IOS Software that could allow an unauthenticated, remote attacker
to cause a memory leak that could lead to a device reload. The
vulnerability is due to incorrect handling of malformed IKE packets by
the affected software. An attacker could exploit this vulnerability by
sending crafted IKE packets to a device configured with features that
leverage IKE version 1 (IKEv1). Although IKEv1 is automatically
enabled  on a Cisco IOS Software when IKEv1 or IKE version 2 (IKEv2)
is configured the vulnerability can be triggered only by sending a
malformed IKEv1 packet. In specific conditions, normal IKEv1 packets
can also cause an affected release of Cisco IOS Software to leak
memory. Only IKEv1 is affected by this vulnerability. An exploit
could cause Cisco IOS Software not to release allocated memory,
causing a memory leak. A sustained attack may result in a device
reload. Cisco has released free software updates that address this
vulnerability. There are no workarounds to mitigate this
vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ike
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5c40d83"
  );
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
if ( version == '15.1(3)MR' ) flag++;
if ( version == '15.1(3)S2' ) flag++;
if ( version == '15.1(3)S3' ) flag++;
if ( version == '15.1(3)S4' ) flag++;
if ( version == '15.1(3)S5' ) flag++;
if ( version == '15.1(3)S5a' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(2)S' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)XA' ) flag++;

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
