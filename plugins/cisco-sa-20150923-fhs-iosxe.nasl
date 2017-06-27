#TRUSTED 7aed6f41689b988ea3e7a9532d4ae27107e2c530a7c585e7e9ddde1bb494de49b14c62a3876a2eff48ccb983f70273f82d6831a2a6a5ba2a3dd4ef15f8a4ecaffd58d8cc7c377169459bc6edfef4b15b2978a7a46129d81f4a3a77da6d57fd34f14927b047dd77a2f128916eb5de56f62124b3876b9166d2b86a1d68d306b98458f2273dbddfc027aea72d2ea942d5a5b105321138fd1d905c12aa25cddec9697da5445ba5e2c7f97bec858b0aed90c598b81bea0341ee69abfcc066880ecbbf517d0b434849d3d81050424c922660a88957ff250eaff03801460dae363bfcc1f1fd523f8cb2772ec05a67237e7791e910ea98c632bd68cb6cb1d2b51acf2750416c1b15fe25a6803f6419f5d2df1aa7727bf0f1e0ea4b89a6f0471380beb9139508292ebc4995c944d1d6cef95b0bfd4bef2910372fc85e0852abde7604c92cb26874e1c1ca11abaccf7cf7c651614ab6bb72fd543e1a742fac8d368adca01dc78cf2d01fe3e474776fb0a708d82ef78d909b04a1ba26cfe262620a2117bd5e1c092bb9ad671813c29b5dd27129a261b3aef43caf13ded68d45117285c47790551d2d734036875bbeb7d2a20a42acb007ddfcfa72ce3914039e96ac3c114ec51805a6ee0ae7c0aef701cd8a32ab24ac945d85613ef3260eacf9e07b16a02621afdac1ed0923d9c0f91a7bd20badd4b3e153e35a015e0e711cebb9350e56c66a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86247);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/03");

  script_cve_id("CVE-2015-6278", "CVE-2015-6279");
  script_osvdb_id(127977, 127978);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo04400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus19794");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-fhs");

  script_name(english:"Cisco IOS XE IPv6 Snooping DoS (cisco-sa-20150923-fhs)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and is configured for IPv6 snooping. It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists in the IPv6 Snooping feature due to
    missing Control Plane Protection (CPPr) protection
    mechanisms. An unauthenticated, remote attacker can
    exploit this to cause a saturation of IPv6 ND packets,
    resulting in a reboot of the device. (CVE-2015-6278)

  - A flaw exists in the IPv6 Snooping feature due to
    improper validation of IPv6 ND packets that use the
    Cryptographically Generated Address (CGA) option. An
    unauthenticated, remote attacker can exploit this, via a
    malformed package, to cause a saturation of IPv6 ND
    packets, resulting in a device reboot. (CVE-2015-6279)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-fhs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7f02f6b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuo04400 and CSCus19794.

Alternatively, as a temporary workaround, disable IPv6 snooping and
SSHv2 RSA-based user authentication.");
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

flag     = FALSE;
override = FALSE;

if (version =='3.2.0SE') flag++;
if (version =='3.2.1SE') flag++;
if (version =='3.2.2SE') flag++;
if (version =='3.2.3SE') flag++;
if (version =='3.3.0SE') flag++;
if (version =='3.3.0XO') flag++;
if (version =='3.3.1SE') flag++;
if (version =='3.3.1XO') flag++;
if (version =='3.3.2SE') flag++;
if (version =='3.3.2XO') flag++;
if (version =='3.3.3SE') flag++;
if (version =='3.3.4SE') flag++;
if (version =='3.3.5SE') flag++;
if (version =='3.4.0SG') flag++;
if (version =='3.4.1SG') flag++;
if (version =='3.4.2SG') flag++;
if (version =='3.4.3SG') flag++;
if (version =='3.4.4SG') flag++;
if (version =='3.4.5SG') flag++;
if (version =='3.4.6SG') flag++;
if (version =='3.5.0E') flag++;
if (version =='3.5.1E') flag++;
if (version =='3.5.2E') flag++;
if (version =='3.5.3E') flag++;
if (version =='3.6.0E') flag++;
if (version =='3.6.0aE') flag++;
if (version =='3.6.0bE') flag++;
if (version =='3.6.1E') flag++;
if (version =='3.6.2E') flag++;
if (version =='3.6.2aE') flag++;
if (version =='3.7.0E') flag++;
if (version =='3.7.1E') flag++;
if (version =='3.9.0S') flag++;
if (version =='3.9.1S') flag++;
if (version =='3.9.2S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0S') flag++;
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
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.12.3S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;
if (version =='3.14.1S') flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  buf = cisco_command_kb_item("Host/Cisco/Config/show-ipv6-snooping-policies", "show ipv6 snooping policies");
  if (check_cisco_result(buf))
  {
    if ("Snooping" >< buf)
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCuo04400 / CSCus19794' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
