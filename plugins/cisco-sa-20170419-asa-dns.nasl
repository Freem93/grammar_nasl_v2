#TRUSTED 0395cc2dd2555c710b7e8974d906686d9c9ff5b938dc33b55e692d9d021d303c46a6d23594a13e728debd7e21886df256e66f30526dfd74f31966651c55c6ed10c58fc9b6a1122f36243fbf73f2f3ddf902b015c06b6a3a7e690b30bbb3a5019aefac4a21721902d46540237156b940746cc48dbdfae5bef492cde7922868aae5e2e77548990827054000cce7c4acb583fd1339e27559fa3d14a4647c24b5ad555dc0e0963dbeaaede2492ebf1b1a97a42fbe34b603c9a202e2dd578a18c1b91596300d7d00492bdf74da2afb302e1958fdb2b1d14c1911e95be744e078c061e176480fe696dce0124021e72cf13140928f936bccfa72182d52540234f593e1a218f852b8a13fec23601317ceb953854d637c5f5dc5f0d0a15b94b6e15e45304c26af3cd5396220388e31d56dae9a5aa1b1aece895c4f95da53587416e6a9953a06b334659abaaca1ec820d08c4e3aa952315140d3bb79929d53b2ddab6fb1968fedf43d001053ab7599a9658c812cbefacc209407d60ad92703165bdc16ab00c1d05ef804c4b66f761e2d923e42b8d38dff7ebf18ac062b4c1f7ebd2d03061400e54f11134adb41e802f957681c5ae289d503ddc5b55e7e6482a075e2579b4cd25c5ee9555d43eb0b48204d97a2f071964e93dfb8c56eb1e9bccbf04e42ebf1cec3a51f664db4bda15ffb822e2518b2ebb44530f5a9de7c5ec185b11acbce2f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99665);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/25");

  script_cve_id("CVE-2017-6607");
  script_bugtraq_id(97933);
  script_osvdb_id(155940);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb40898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-dns");

  script_name(english:"Cisco ASA Software DNS Response Message Handling DoS (cisco-sa-20170419-asa-dns)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the DNS
code due to improper handling of crafted DNS response messages. An
unauthenticated, remote attacker can exploit this, via a specially
crafted DNS response, to cause the device to reload or corrupt the
local DNS cache information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-dns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75ae1722");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb40898");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-dns.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

cbi = 'CSCvb40898';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.12)"))
  fixed_ver = "9.1(7.12)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.18)"))
  fixed_ver = "9.2(4.18)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(3.12)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(3.12)"))
  fixed_ver = "9.4(3.12)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3.2)"))
  fixed_ver = "9.5(3.2)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(2.2)"))
  fixed_ver = "9.6(2.2)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config dns server-group", "show running-config dns server-group");

  if (check_cisco_result(buf))
  {
    if (
      ("DNS server-group" >< buf) &&
      (preg(multiline:TRUE, pattern:"name-server [0-9\.]+", string:buf))
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because a DNS server IP address is not configured under a DNS server group");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show running-config dns server-group")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
