#TRUSTED 0a5d765cee7d2ccdb3827379f0493e196e665d4c3a689facd2eff8c743230b2cd21824be7ff0ea31ac0ec74d473b2edebcda71a5f236a0f7c9173900ec783825e27c587dfab95ab9fe411356e4af9813a30dc664e12f374e60378984e55f3020c6aa71af51d85ff71d15503005b44de10b625323264e5cdfadfe3f9c7e9f15513862aa524aacf7515f242b50601c24720ad855c246a9eb9aea1d87aae7b826a0fc53e97656d7d73aad53ec9748fc84adf901a4763ca8e5debad0169374e16e2b53f7ddab2bd977a1cc2a3822522674b93e3ab3b2984ea065c9f91e962d59b6665bd7fd41231b37280abc09c8a7ca82bb61db7992c06286fdd66566c2a3d98f75df28a9d07c8a48090ab29c0dcc321ad8b2c29b1f8fcd588b7940dcf98d95edd6813a8854960e728f1f0490fe256363f296091ca2604a5ebdb7e00b7f2dca228e30754e652a15c6523ddcbbbf74e6d1a3f4b5c68d4e43b6ae2429c43f91e5e2b22b4ac0eff300742f0e205188dda7195987300e7bb2f7d458215b4e1572d2a055003c40b5ae59f4e1d19d905c1b24fee8e2f47755ff8921e04c484c89a033d0b51e12d65fbbc1326f34787cadc29f5e5626dfb1335e56ba9f566adc6ec0d57474ecaf6f400bfa90458e7d54a4d462e3056129d8e1ab65101eae5ace96c83c2d6385f9d361fab3874330e59f6e892d8f0e1d30d351208cef4bcbf1e95ed3cea5f8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91962);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/07/06");

  script_cve_id("CVE-2016-1295");
  script_osvdb_id(133009);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo65775");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160115-asa");

  script_name(english:"Cisco ASA AnyConnect Client Authentication Attempt Handling Information Disclosure (cisco-sa-20160115-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Adaptive
Security Appliance (ASA) software running on the remote device is
affected by an information disclosure vulnerability due to a failure
to protect sensitive data during a Cisco AnyConnect client
authentication attempt. An unauthenticated, remote attacker can
exploit this, by attempting to authenticate to the Cisco ASA with
AnyConnect, to disclose sensitive data, including the ASA software
version

Note that the SSL VPN feature must be enabled for the device to be
affected by this vulnerability.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160115-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fea9000");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuo65775.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = NULL;

if (ver =~ "^8\.4[^0-9]")
  fixed_ver = "Refer to vendor.";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.100)"))
  fixed_ver = "9.1(6.100)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4.11)"))
  fixed_ver = "9.2(4.11)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(1.99)"))
  fixed_ver = "9.3(1.99)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(0.109)"))
  fixed_ver = "9.4(0.109)";
if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

flag     = FALSE;
override = FALSE;

# Check if SSL VPN (WebVPN) feature is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"enable", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
