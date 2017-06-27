#TRUSTED a6115a189fdfc71a8120191848dc414cae42354dfb15753e154e8bd7f9e06445a55c0df18c3bf7ddf295d63dc1fcff5e3261f59754e74f58f7746635ea5d013b442b3cb919de7f14157211497336b0be01d7a1b07e372ed438c0835b61cf9ad4f38b81b3bc6f290ca7a82e3b2e148892d6032b39d01c070f84c867ea2dba5ff0fb91e449ae9f8fbcc59ecfb371f812f0e0db25fce5105b92d8f22d7c2d367fdee02dfa7291347a4ae73f23937cdb5ee76dc9f57d8529d603e309664bde779a2e490b91ab2453ca165feda893cb8352443bba91ea6ad56609be4189340f5e194ff3974ec0358825ad41d61759c012a9378bca2b1696ed9efe11ef2ca1496a4fa73767d2c2daf1c9ea3f11b7b66201cb9f1f733691ba4354ba6eae5ca8e2ffa77d2182caac0f06ffebd7c3820674227af2d251581e4bc07a5ef7e72e4979eaca08e5dbc43b6c05299a5cc2461ebb6d4fde0c67f0d5958c700a2bafc95d04e415ea5d442c375ad9d8e77c86bf7744cf7851ecf34f40dbaef14c652ebbde0e96165d1ac7bee87d7711371fbbb162719484e121899172fc33e335508071c1e95a8ee8e2f9db6b5d0c4aa07ebf72caceb3dea6df0331044e82c66c390a6443b2b93ba3c299a0fcecb7ee1f1d1430375ffab398fc3ae48f47f7f251794894b03c80c390c6d577884a6f835d6dab75e4f8f127a57c6d3c62612f9c169fa71ed0f15eba56
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-c10k-tunnels.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62371);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2012-4620");
  script_osvdb_id(85811);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts66808");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-c10k-tunnels");

  script_name(english:"Cisco IOS Software Tunneled Traffic Queue Wedge Vulnerability (cisco-sa-20120926-c10k-tunnels)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a queue wedge vulnerability that can be
triggered when processing IP tunneled packets. Only Cisco IOS Software
running on the Cisco 10000 Series router has been demonstrated to be
affected. Successful exploitation of this vulnerability may prevent
traffic from transiting the affected interfaces. Cisco has released
free software updates that addresses this vulnerability. There are no
workarounds for this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-c10k-tunnels
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9f98e6e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-c10k-tunnels."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
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
if ( version == '12.2(33)SB' ) flag++;
if ( version == '12.2(33)SB1' ) flag++;
if ( version == '12.2(33)SB10' ) flag++;
if ( version == '12.2(33)SB11' ) flag++;
if ( version == '12.2(33)SB1a' ) flag++;
if ( version == '12.2(33)SB1b' ) flag++;
if ( version == '12.2(33)SB2' ) flag++;
if ( version == '12.2(33)SB3' ) flag++;
if ( version == '12.2(33)SB4' ) flag++;
if ( version == '12.2(33)SB5' ) flag++;
if ( version == '12.2(33)SB6' ) flag++;
if ( version == '12.2(33)SB6a' ) flag++;
if ( version == '12.2(33)SB6aa' ) flag++;
if ( version == '12.2(33)SB6b' ) flag++;
if ( version == '12.2(33)SB7' ) flag++;
if ( version == '12.2(33)SB8' ) flag++;
if ( version == '12.2(33)SB8b' ) flag++;
if ( version == '12.2(33)SB8c' ) flag++;
if ( version == '12.2(33)SB8d' ) flag++;
if ( version == '12.2(33)SB8e' ) flag++;
if ( version == '12.2(33)SB8f' ) flag++;
if ( version == '12.2(33)SB8g' ) flag++;
if ( version == '12.2(33)SB9' ) flag++;
if ( version == '12.2(33)SRC' ) flag++;
if ( version == '12.2(33)SRC1' ) flag++;
if ( version == '12.2(33)SRD' ) flag++;
if ( version == '12.2(33)XND' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)XNE2' ) flag++;
if ( version == '12.2(33)XNE3' ) flag++;
if ( version == '12.2(34)SB1' ) flag++;
if ( version == '12.2(34)SB2' ) flag++;
if ( version == '12.2(34)SB3' ) flag++;
if ( version == '12.2(34)SB4' ) flag++;
if ( version == '12.2(34)SB4a' ) flag++;
if ( version == '12.2(34)SB4b' ) flag++;
if ( version == '12.2(34)SB4c' ) flag++;
if ( version == '12.2(34)SB4d' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)S4' ) flag++;
if ( version == '15.0(1)S4a' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_interface_brief", "show ip interface brief");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Tunnel", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
