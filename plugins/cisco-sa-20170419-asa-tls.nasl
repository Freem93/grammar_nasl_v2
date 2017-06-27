#TRUSTED 2c6f8aa764da4393de33596c130ebc0c86f7f29d43c593a2487cc90d995ff46f6f9d63690364b9368b187401fad6c4f986ef760a9e88855196e4f87c3955a0d303ceb1267e6ba900f5b96d0360eff57f8bc229c08cb19041df7f1ac6bebf5e07b013646543c72c6d376997c8f91f38aba32bdb611af5d462bac8ed06806b4b53972f126ce0f281def924af40f48b1c94a04fb755a848b9a57d7981826d54e68effd2dc555b7c9dc9375e50b7404d30420d66743e2c0654c8752cbb0f6d988b814924e037775ee50e0d23bf62eabebf7b05e22386a5f528c13968a32060a15027e79fb4f0b4a36062c3d5b0ca833e9bc3b927bff75517aedaf9d94226f76eff9fdf5cff43f6be0ffbe42494bef68c2f2911e356ac234bd992b17e35a181df64e613e1e00cde27824eef8a81bdb1cb329b077e0af53f6438aea04c8d6cb1baa371135c4e6afe974a6123a11ddfffc6bee9e3affa08a8154684167d8dd67208bf59188794f602d6cbada021e21588f78a8dd525ff358600dc6a12b25edaa141f9a797503d5e595d4dcf61cc03a906cfa8e9573f2f325a25d646b5ed268e95e1eef9860dc703a5d24022559e49928e2c45e4147a3bc3ff60edfa15d6dab3ca0d29875e88016008fa4c11cebc6f17e46760b7fa9cd07f726e21abf6b1cf9845b6f8c7cdb5c5e88b53456e77292a004a817966c9ed3eac6e052fa4a2bc145115d346e3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99667);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/25");

  script_cve_id("CVE-2017-6608");
  script_bugtraq_id(97937);
  script_osvdb_id(155942);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv48243");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-tls");

  script_name(english:"Cisco ASA Software SSL / TLS Packet Handling DoS (cisco-sa-20170419-asa-tls)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the Secure
Sockets Layer (SSL) and Transport Layer Security (TLS) code due to
improper parsing of crafted SSL or TLS packets. An unauthenticated,
remote attacker can exploit this, via specially crafted packets, to
cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-tls
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?262b831a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv48243");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-tls.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

cbi = 'CSCuv48243';

if (version =~ "^8\.4[^0-9]" && check_asa_release(version:version, patched:"8.4(7.31)"))
  fixed_ver = "8.4(7.31)";
else if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7)";
else if (version =~ "^9\.0[^0-9]" && check_asa_release(version:version, patched:"9.0(4.39)"))
  fixed_ver = "9.0(4.39)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7)"))
  fixed_ver = "9.1(7)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.6)"))
  fixed_ver = "9.2(4.6)";
else if (version =~ "^9\.3[^0-9]" && check_asa_release(version:version, patched:"9.3(3.8)"))
  fixed_ver = "9.3(3.8)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(2)"))
  fixed_ver = "9.4(2)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(2)"))
  fixed_ver = "9.5(2)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show asp table socket | include SSL", "show asp table socket | include SSL");

  if (check_cisco_result(buf))
  {
    if (
      ("SSL" >< buf)
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because it is not configured to process SSL or TLS packets");
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
    cmds     : make_list("show asp table socket | include SSL")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
