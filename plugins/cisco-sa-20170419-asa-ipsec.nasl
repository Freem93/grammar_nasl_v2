#TRUSTED 8fb1fef3f5514a8a7ee993752aabc314e24be03123690bcfa5df0d0fdfbaebdb9116acc24c45ddaeba7271854424001a89c4392eb066c1ba739cf0eac257ee3e20188b8882ee785a38679789971e5475791efed5e69f97c80b70db11b9487e6c53ce1a6cddf3aecdcbba84442c0de4787d53a03df5581e821c941086c5f7908a199f6a2cb341445c0347fc3abdb9f857e202df38f2c177f015c0602dd619e0cb6614fb8aa600d3a4c0da1a4d477d138e5259329e0f75e4be3b889e5f9be29efdee3fb19b8b95ee18133074dcf1e96a1d39a50d32172d1e9515ca004a04de3358a310ffe354e2fc16da9f50adfa05df70b170f78cd41b33f5ecff0a9d98964586344684ab4e5b806dfede1abc88a57db4e534fbb9cc6e594aee706498859c1667cba771fdafcc7176687376a03ade201e48a5c18f5084bb403ea83f9b2337f8fe3b9f3e4e9735b9fc740b4606b2226d0d6670130d0ef65f059b17d191bd028b2ae1291b39cac696bd3e71a304b5fec83eed488d24f94f66ac9cc6a5a55c640d0a5c525341d22ae0a364289f484ccba7d9a5b1f6f3eef435de11d544d74f42c374bdcbd6e562fd0693315a5398ee91fd5bde470404fa1d09e658337c78a5076fb8253d05d963cbb5c0e8f4d296cdcf3ac797107cc7775ee727cda7c2e77b24ce168e3ea7213e3f2837bc34a7659a910dafdbcfacf507297414a165b94889da00ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99666);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/25");

  script_cve_id("CVE-2017-6609");
  script_bugtraq_id(97936);
  script_osvdb_id(155941);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun16158");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-ipsec");

  script_name(english:"Cisco ASA Software IPsec Packet Handling DoS (cisco-sa-20170419-asa-ipsec)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the IPsec
code due to improper parsing of malformed IPsec packets. An
authenticated, remote attacker can exploit this, via specially crafted
IPsec packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-ipsec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ea5056");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun16158");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-ipsec.");
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

cbi = 'CSCun16158';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.8)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.8)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.8)"))
  fixed_ver = "9.1(7.8)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.15)"))
  fixed_ver = "9.2(4.15)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4)"))
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3.2)"))
  fixed_ver = "9.5(3.2)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(2)"))
  fixed_ver = "9.6(2)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto map | include interface", "show running-config crypto map | include interface");

  if (check_cisco_result(buf))
  {
    if (
      ("crypto map" >< buf)
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because it is not configured to terminate IPsec VPN connections");
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
    cmds     : make_list("show running-config crypto map | include interface")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
