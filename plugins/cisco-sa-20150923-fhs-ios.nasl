#TRUSTED 66679a966188cae63be73494681090702da6856b3025cb9462f525ed2bbe2e50c176a4e6782d85bf230364e1bbe5831f2d906aab6d5b3d66d09c5a803ac7f4e8f9e74fb990a279e81c15693f392df3be07e3742ebbcdd7cc76020147c00ae24a2e56dbf8f01ac578b591f9ccebeb6917e6000046a818e872054fe5d9055065fb1d91c3cad05488a68db2986689dfd178b334d59849289bc357effbf66bd12d85609d14475075e8c2fb7a31b49ffedf94324ca9b432443669f463322cc1f6beb27dff4f24d4614e48d1d97a76509f85a4b94ff081701917e76a9bc8f4518cac65fbf5842fb11784be604d62c80afaf5fec7d1963611b4b2262f83ee2b6bf9dd6c78cb3e901ec3bf057d6ceb6757194debed3d5eead094686d79c8d5db4cf685535ef963340a6a6f2af77ba89a70e2ed37e64cf2c06fb733512928093353c93d2c14f7cb882511602ebeebf357ab373efd7eb1e22f9ec14b78c01410ab77525912b82aa2228f7b6812271e733da0a557d0584d577c38aa1587f4e0c70e52a486833075f45df22203f0c4b82c91c178f589bc7dfa42dc430f40f07892c9d2bba5b7323ff16f5a6fd8485f8cda6acd49f374641ec83462b8ff468d39c8a947b89fbe752992a0f68ef794bbda67468e0b7aca945a77d861bf8ba67b079aa505b29e60f0c943ce66c083e64716645a6bf4d2cd562d6f18b9719c796c192863036b802c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description){

  script_id(86246);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/03");

  script_cve_id("CVE-2015-6278", "CVE-2015-6279");
  script_osvdb_id(127977, 127978);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo04400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus19794");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-fhs");

  script_name(english:"Cisco IOS IPv6 Snooping DoS (cisco-sa-20150923-fhs)");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device missing vendor-supplied security patches,
and is configured for IPv6 snooping. It is, therefore, affected by the
following vulnerabilities :

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;

if (ver =='12.2(50)SY') flag++;
if (ver =='12.2(50)SY1') flag++;
if (ver =='12.2(50)SY2') flag++;
if (ver =='12.2(50)SY3') flag++;
if (ver =='12.2(50)SY4') flag++;
if (ver =='15.0(1)EX') flag++;
if (ver =='15.0(1)SY') flag++;
if (ver =='15.0(1)SY1') flag++;
if (ver =='15.0(1)SY2') flag++;
if (ver =='15.0(1)SY3') flag++;
if (ver =='15.0(1)SY4') flag++;
if (ver =='15.0(1)SY5') flag++;
if (ver =='15.0(1)SY6') flag++;
if (ver =='15.0(1)SY7') flag++;
if (ver =='15.0(1)SY7a') flag++;
if (ver =='15.0(1)SY8') flag++;
if (ver =='15.0(2)EA2') flag++;
if (ver =='15.0(2)EJ') flag++;
if (ver =='15.0(2)EJ1') flag++;
if (ver =='15.0(2)EZ') flag++;
if (ver =='15.0(2)SE') flag++;
if (ver =='15.0(2)SE1') flag++;
if (ver =='15.0(2)SE2') flag++;
if (ver =='15.0(2)SE3') flag++;
if (ver =='15.0(2)SE4') flag++;
if (ver =='15.0(2)SE5') flag++;
if (ver =='15.0(2)SE6') flag++;
if (ver =='15.0(2)SE7') flag++;
if (ver =='15.1(1)SY') flag++;
if (ver =='15.1(1)SY1') flag++;
if (ver =='15.1(1)SY2') flag++;
if (ver =='15.1(1)SY3') flag++;
if (ver =='15.1(1)SY4') flag++;
if (ver =='15.1(1)SY5') flag++;
if (ver =='15.1(2)SG') flag++;
if (ver =='15.1(2)SG1') flag++;
if (ver =='15.1(2)SG2') flag++;
if (ver =='15.1(2)SG3') flag++;
if (ver =='15.1(2)SG4') flag++;
if (ver =='15.1(2)SG5') flag++;
if (ver =='15.1(2)SY') flag++;
if (ver =='15.1(2)SY1') flag++;
if (ver =='15.1(2)SY2') flag++;
if (ver =='15.1(2)SY3') flag++;
if (ver =='15.1(2)SY4') flag++;
if (ver =='15.1(2)SY4a') flag++;
if (ver =='15.1(2)SY5') flag++;
if (ver =='15.2(1)E') flag++;
if (ver =='15.2(1)E1') flag++;
if (ver =='15.2(1)E2') flag++;
if (ver =='15.2(1)E3') flag++;
if (ver =='15.2(1)SY') flag++;
if (ver =='15.2(1)SY0a') flag++;
if (ver =='15.2(2)E') flag++;
if (ver =='15.2(2)E1') flag++;
if (ver =='15.2(2)E2') flag++;
if (ver =='15.2(2)EA1') flag++;
if (ver =='15.2(2a)E1') flag++;
if (ver =='15.2(3)E') flag++;
if (ver =='15.2(3)E1') flag++;
if (ver =='15.2(3a)E') flag++;
if (ver =='15.2(4)S') flag++;
if (ver =='15.2(4)S1') flag++;
if (ver =='15.2(4)S2') flag++;
if (ver =='15.2(4)S3') flag++;
if (ver =='15.2(4)S3a') flag++;
if (ver =='15.2(4)S4') flag++;
if (ver =='15.2(4)S4a') flag++;
if (ver =='15.2(4)S5') flag++;
if (ver =='15.2(4)S6') flag++;
if (ver =='15.3(1)S') flag++;
if (ver =='15.3(1)S2') flag++;
if (ver =='15.3(2)S') flag++;
if (ver =='15.3(2)S0a') flag++;
if (ver =='15.3(2)S1') flag++;
if (ver =='15.3(2)S2') flag++;
if (ver =='15.3(3)S') flag++;
if (ver =='15.3(3)S1') flag++;
if (ver =='15.3(3)S2') flag++;
if (ver =='15.3(3)S3') flag++;
if (ver =='15.3(3)S4') flag++;
if (ver =='15.4(1)S') flag++;
if (ver =='15.4(1)S1') flag++;
if (ver =='15.4(1)S2') flag++;
if (ver =='15.4(1)S3') flag++;
if (ver =='15.4(2)S') flag++;
if (ver =='15.4(2)S1') flag++;
if (ver =='15.4(2)S2') flag++;
if (ver =='15.5(1)S') flag++;
if (ver =='15.5(1)S1') flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show-ipv6-snooping-policies", "show ipv6 snooping policies");
  if (check_cisco_result(buf))
  {
    if ("Snooping" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug IDs     : CSCuo04400 / CSCus19794' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
