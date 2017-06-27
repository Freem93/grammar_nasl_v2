#TRUSTED 0c8d16680c3d9af90d70876f432621b4adeb0bad6e8f0e876b0b8a080e4ee59f62c932dc81048bcb507c4162f4bc4339aca1e7b14eed28aad65c0e04718f3554b22787e524c81214e3c0cfbadcfb9f9a3ce5d71ac2e300a27aeafaee5d070eea662be2ce744035dcf7e00497c20108081dcf271b0367812310d945e208c4957350b9c4aceba6873dab7f68fe9ab37cda64b57b1ad56c35be3a021ecf6f40b4298e8def86155afaa6730a4be38bcba86bd47aa5c84780b877a134de7f06b0f0302090144cc669560702a026209591a870f50ed6a5defdf4386cc54ebc0f2764c24615b78771e18428786b683acff7daddb4e1f6d19962813747dcc70b23f158b8e32acfe2bc407740dc4d25808f2155dfe400c0d5f37082b74bd5eb06c899cc1aed7a322f8ca99c7ac5efe588671c61b7729816a944d23889785ca35499766faa6f5ed54ccc3fa50efecbe459fab2fe4174d8ecb6ee433aae8e5517a7eca220c8835e2cf1e75c320923a486122fd6d291b8e7e5772fd00ba59cc34593427771d9178cb81f5a8addc252c044cb000485ad42fe87d840677bcc9511fa58fddcf24b9d20e2ae393e8d59db41acad3f0665338e1167fd84ec0090e3905420cbb314aff7193fa795036e32b99de0ba37d582d8bc1a4b2d949e3b52aae7b385b65fcda210fffffaf54c3471b1f88704ad29f097a7e1adc060ba13a956f175ef9825114d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99668);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/25");

  script_cve_id("CVE-2017-6610");
  script_bugtraq_id(97934);
  script_osvdb_id(155943);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz11685");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-xauth");

  script_name(english:"Cisco ASA Software IKEv1 XAUTH Parameter Handling Remote DoS (cisco-sa-20170419-asa-xauth)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the
Internet Key Exchange Version 1 (IKEv1) XAUTH code due to improper
validation of the IKEv1 XAUTH parameters passed during an IKEv1
negotiation. An authenticated, remote attacker can exploit this, via
specially crafted parameters, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-xauth
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6b8b6cb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-xauth.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^1000V' && # 1000V
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCuz11685';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.7)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.7)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.7)"))
  fixed_ver = "9.1(7.7)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.11)"))
  fixed_ver = "9.2(4.11)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4)"))
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3)"))
  fixed_ver = "9.5(3)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(1.5)"))
  fixed_ver = "9.6(1.5)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto map | include interface|dynamic", "show running-config crypto map | include interface|dynamic");

  if (check_cisco_result(buf))
  {
    if ("dynamic" >< buf)
    {
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show running-config all tunnel-group | include xauth", "show running-config all tunnel-group | include xauth");
      if (check_cisco_result(buf2))
      {
        if ("ikev1 user-authentication xauth" >< buf2)
          flag = TRUE;
      }
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because it is not configured to terminate IKEv1 remote access VPN connections and XAUTH is used for user authentication");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show running-config crypto map | include interface|dynamic", "show running-config all tunnel-group | include xauth")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
