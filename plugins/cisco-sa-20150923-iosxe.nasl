#TRUSTED 847860c9658b594df54f1a299a3981c092109ffa31396c3dc37ad1e04b6ff7355c4923c9960e4417f51630b836de79e38f15d791845f7c7f0ac19e46661b58fb0cc7af51f4473b59a518386e504f9c3fbaeeeb31dddf579d41c59bc55519d7d2b8660ed7ac2c0e4074ff08a9a17c97048663d9a324b4914aaab955586e1f3b3169fa151336f3a994ffa8a9aea20edc29d7594568021ec7057b9fa6c17b64439fde758f8ab798989a1ea5d1bededbcc3e2153743d1772e8c6419a1dafc1fbcfa6e2c64d6b7052900d6b919d759fec185fa11544ec46e84270b344dacba167f899b9c73ded15f56117370c75f9723bacaf2d0bd7cfafba604e1734239f48832b2dbfb507a355497445667bbbef633ececf401bc5b935a897f3b6512f1df87a4a7773a6860a63ba2de9f7d403118d2fd4d8e1219205d2c523483102825a9487a9eec41023795c4e0841c3bb01ce3a047b74b864b3b1d4441bda0efff6b5929c24ad376f6b10aaaeea0cd70e50517e0ac363d7be6bf3da44f29ed98b2f11778bf59714b558b404146a7ce2c005e63d084493804254d40d1b819a2370787e513ba531416ee1cf5e0846a4f9cf3bfdd2831182f57906c9ecb7e2f9ed7c1ce1fed6f16153ff7425b5089026f7080c4110fae8a4b655482372256da8bec8a6216485da38f374c3610acfbf2076908497a08f90e8ed721c27b1bd76e5fd5c5d0495b4cae0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86248);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/03");

  script_cve_id("CVE-2015-6282");
  script_osvdb_id(127979);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut96933");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-iosxe");

  script_name(english:"Cisco IOS XE Network Address Translation and Multiprotocol Label Switching DoS (CSCut96933)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and is configured for Network Address Translation (NAT)
and/or Multiprotocol Label Switching (MPLS). It is, therefore,
affected by a flaw in the NAT and MPLS services due to improper
processing of IPv4 packets. An unauthenticated, remote attacker can
exploit this, via a crafted IPv4 package, to cause the device to
reboot.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-iosxe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?332c6f37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut96933.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (
  !(
      "ASR1k" >< model ||
      model =~ '^ASR 10[0-9][0-9]($|[^0-9])' ||
      "ISR4300"  >< model ||
      "ISR4400"  >< model ||
      "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

flag     = FALSE;
override = FALSE;

if (version =='2.1.0') flag++;
if (version =='2.1.1') flag++;
if (version =='2.1.2') flag++;
if (version =='2.1.3') flag++;
if (version =='2.2.1') flag++;
if (version =='2.2.2') flag++;
if (version =='2.2.3') flag++;
if (version =='2.3.0') flag++;
if (version =='2.3.0t') flag++;
if (version =='2.3.1t') flag++;
if (version =='2.3.2') flag++;
if (version =='2.4.0') flag++;
if (version =='2.4.1') flag++;
if (version =='2.4.2') flag++;
if (version =='2.4.3') flag++;
if (version =='2.5.0') flag++;
if (version =='2.5.1') flag++;
if (version =='2.5.2') flag++;
if (version =='2.6.0') flag++;
if (version =='2.6.1') flag++;
if (version =='2.6.2') flag++;
if (version =='2.6.2a') flag++;
if (version =='3.1.0S') flag++;
if (version =='3.1.1S') flag++;
if (version =='3.1.2S') flag++;
if (version =='3.1.3S') flag++;
if (version =='3.1.4S') flag++;
if (version =='3.1.4aS') flag++;
if (version =='3.1.5S') flag++;
if (version =='3.1.6S') flag++;
if (version =='3.2.0S') flag++;
if (version =='3.2.1S') flag++;
if (version =='3.2.2S') flag++;
if (version =='3.2.3S') flag++;
if (version =='3.3.0S') flag++;
if (version =='3.3.1S') flag++;
if (version =='3.3.2S') flag++;
if (version =='3.4.0S') flag++;
if (version =='3.4.0aS') flag++;
if (version =='3.4.1S') flag++;
if (version =='3.4.2S') flag++;
if (version =='3.4.3S') flag++;
if (version =='3.4.4S') flag++;
if (version =='3.4.5S') flag++;
if (version =='3.4.6S') flag++;
if (version =='3.5.0S') flag++;
if (version =='3.5.1S') flag++;
if (version =='3.5.2S') flag++;
if (version =='3.6.0S') flag++;
if (version =='3.6.1S') flag++;
if (version =='3.6.2S') flag++;
if (version =='3.7.0S') flag++;
if (version =='3.7.1S') flag++;
if (version =='3.7.2S') flag++;
if (version =='3.7.3S') flag++;
if (version =='3.7.4S') flag++;
if (version =='3.7.5S') flag++;
if (version =='3.7.6S') flag++;
if (version =='3.7.7S') flag++;
if (version =='3.8.0S') flag++;
if (version =='3.8.1S') flag++;
if (version =='3.8.2S') flag++;
if (version =='3.9.0S') flag++;
if (version =='3.9.1S') flag++;
if (version =='3.9.2S') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0aS') flag++;
if (version =='3.10.1S') flag++;
if (version =='3.10.2S') flag++;
if (version =='3.10.3S') flag++;
if (version =='3.10.4S') flag++;
if (version =='3.10.5S') flag++;
if (version =='3.11.0S') flag++;
if (version =='3.11.1S') flag++;
if (version =='3.11.2S') flag++;
if (version =='3.11.3S') flag++;
if (version =='3.11.4S') flag++;
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.12.3S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;
if (version =='3.14.1S') flag++;
if (version =='3.14.2S') flag++;
if (version =='3.14.3S') flag++;
if (version =='3.14.4S') flag++;
if (version =='3.15.0S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  # Look for NAT
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-include-ip-nat", "show running-config | include ip nat");
    if (check_cisco_result(buf))
    {
      if (
        "ip nat inside" >< buf ||
        "ip nat outside" >< buf
      )
        flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
  }

  # Look for MPLS
  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-interface", "show running-config interface");
  if (check_cisco_result(buf))
  {
    pieces = split(buf, sep:"interface", keep:FALSE);
    foreach piece (pieces)
    {
      if (
        "mpls ip" >< piece &&
        ("ip nat inside" >< piece || "ip nat outside" >< piece)
      ) { flag = TRUE; override = FALSE; }
    }
  }
  else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCut96933' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report+cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));

}
else audit(AUDIT_HOST_NOT, "affected");
