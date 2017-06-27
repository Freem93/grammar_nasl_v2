#TRUSTED 45ab5591e3944d9de9ec5ed0d2f96dfabe7c872a17e8304505e47a75481c4fe1aec7a6d320207a24a020821c44bd31cf7db6093ca0573f1f258ccc097559360e550bfb86b25b3a4b91479059b8a047860ba7abae66140d1a8027d6cda9799bb760b5607677ef9fc5ee18aa1c89cf7c61e7e6d00311af588b1a9af8f379bea8e0e5711af4881f342fe967ed0775209eaa55e94fc963776c46ae2d426fbe7a829f298c24bc911f8ca421e30c3f4d293e25186becfad92fb3680a83e56a64dfd0002808bdf456fe080c123a108671ab983ab0eecc9efecdcd6b19dbf0d0b6f82bcb52b055919f9550dbdd4a8bbd8b5d6dbb6d3e0c1a127648bb440774ccfa85c238616e6700cc892a6dbf52bd6a7c5afb4aafebe566085c4b6b72c0a9efa424649e0a47e036c590453f64de3f20425846c015efd28ea818cc565629edb1140f800a6ca37694ed8243237348ffa05b45a43c329a35844b1ee11489263446f94c6e563f5c5b7a564f13b0293ca4370b2c4de74de76bfce3633928c586f68cbbdf0ef395de680dea11b9441dbd5bedbf66df7f2e6a931e03df5d6a540b42d171f7061fea6062205b88d964986f60abbd87e0025a3e0b9ad030c42dd5eaf102bc2bfc0f52805cfaef1764b592819673b3bdb718785bb67df6b1ac532181df29427127c9dfd41373cc3f3c83682eca80e24d9ec2b04f24503bf0431cd336219edb6aaea2
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131023-iosxr.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71438);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/14");

  script_cve_id("CVE-2013-5549");
  script_bugtraq_id(63298);
  script_osvdb_id(98884);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh30380");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131023-iosxr");

  script_name(english:"Cisco IOS XR Software Route Processor Denial of Service Vulnerability (cisco-sa-20131023-iosxr)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software Releases 3.3.0 to 4.2.0 contain a vulnerability
when handling fragmented packets that could result in a denial of
service (DoS) condition of the Cisco CRS Route Processor cards listed in
the 'Affected Products' section of this advisory.  The vulnerability is
due to improper handling of fragmented packets.  The vulnerability could
cause the route processor, which processes the packets, to be unable to
transmit packets to the fabric.  Customers that are running version
4.2.1 or later of Cisco IOS XR Software, or that have previously
installed the Software Maintenance Upgrades (SMU) for Cisco bug ID
CSCtz62593 are not affected by this vulnerability.  Cisco has released
free software updates that address this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131023-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?248a5be7");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131023-iosxr."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

cbi = "CSCuh30380";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '3.8.1' ) flag++;
if ( version == '3.8.2' ) flag++;
if ( version == '3.8.3' ) flag++;
if ( version == '3.8.4' ) flag++;
if ( version == '3.9.0' ) flag++;
if ( version == '3.9.1' ) flag++;
if ( version == '3.9.2' ) flag++;
if ( version == '3.9.3' ) flag++;
if ( version == '4.0.1' ) flag++;
if ( version == '4.0.3' ) flag++;
if ( version == '4.0.4' ) flag++;
if ( version == '4.1.0' ) flag++;
if ( version == '4.1.1' ) flag++;
if ( version == '4.1.2' ) flag++;
if ( version == '4.2.0' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"CRS-16-RP", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (!flag)
{
  if ( version == '4.0.3' ) flag++;
  if ( version == '4.0.4' ) flag++;
  if ( version == '4.1.0' ) flag++;
  if ( version == '4.1.1' ) flag++;
  if ( version == '4.1.2' ) flag++;
  if ( version == '4.2.0' ) flag++;

  if (get_kb_item("Host/local_checks_enabled"))
  {

    if (flag)
    {
      flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"CRS-16-PRP", string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
