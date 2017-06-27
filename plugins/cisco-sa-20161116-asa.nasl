#TRUSTED 14c592ea21a866cf229b4e4f9e4981f8b2cad4ac7d8d335b972e2f4e92a4c37f688fc2210b2bae478f3113af89feeb4359d3fd0787482d75982be266ea3119259a52f1758056223c6f7d5e2f8ad977553884b8a85f38e036fd96200a2bfd794ff385c18394d728c3120a463f324a3fd6ecf6275eebecb1a0fe12201ec5322fab7fb9da009fc0e95ac56a2a98edd0d2725b406ad36c240bbb8d2722cf58f83aeff7163d023c9792918f79ad328959e6e11e62f60566880c4a26102e456a0a53dbada0f0ca0e9cd364b639bd45f8046546b1f641437c318ae92974dae2f23b2081716e87c6276dbeed01f2c16e80826850cf8fef8e07e7b0b8ad0b341a81e5ffb25f1c0d1f0495de9bc3fd56606825068d1c5a07fe2499f281de1ab2f5e110869f408105685fc28da83530fd14fc3df4171291cceeb021b93bdd928f0c0e7f33a49eb3ef2d7b253b1c30aea13175eaf182b6f6a09cddf2177e0af50d4d730635ddf520491dc299d74a35ad2202dbe3c04f1f34921a9cd99e2dac1149f9c3bc36f3b464ae3b192e86e08555dac3b3583e5ec84212a56336dd2b64552f5160f4927cde292b650a032ae010dc23d9356e787afcd5bc7668ce8839ae8b648e26f5e86434d02fab225a9085cfd4c5ab820b31147316ebede4d606db331143defb60266d467a5ae13453a8648bba68f7a280a237dd5c2306229f4041b0a759d64ec0279b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96047);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/05");

  script_cve_id("CVE-2016-6461");
  script_bugtraq_id(94365);
  script_osvdb_id(147430);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva38556");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-asa");
  script_xref(name:"IAVB", value:"2016-B-0167");

  script_name(english:"Cisco ASA Web Interface Remote XML Command Injection (cisco-sa-20161116-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by an XML command injection vulnerability in the
web-based management interface due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via specially crafted XML input, to inject arbitrary XML
commands, resulting in an impact to the integrity of the device.

Note that Cisco considers this vulnerability to be low/medium
severity, and as a result the existing check information may not be
complete from the vendor. For additional verification, please contact
TAC Cisco support.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbeb50dc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva38556");
  # http://www.cisco.com/c/en/us/support/web/tsd-cisco-worldwide-contacts.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e13eb27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva38556.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

cbi = 'CSCva38556';

vulniosarray = make_array(
  "9.1", make_list("9.1(6.10)",
                   "9.1(7.4)",
                   "9.1(7.6)",
                   "9.1(7.7)",
                   "9.1(7.9)",
                   "9.1(7.11)"),
  "9.2", make_list("9.2(1)",
                   "9.2(2)",
                   "9.2(2.4)",
                   "9.2(2.7)",
                   "9.2(2.8)",
                   "9.2(3)",
                   "9.2(3.3)",
                   "9.2(3.4)",
                   "9.2(0.0)",
                   "9.2(0.104)",
                   "9.2(3.1)",
                   "9.2(4)",
                   "9.2(4.2)",
                   "9.2(4.4)",
                   "9.2(4.8)",
                   "9.2(4.10)",
                   "9.2(4.13)",
                   "9.2(4.14)",
                   "9.2(4.16)",
                   "9.2(4.17)"),
  "9.3", make_list("9.3(1)",
                   "9.3(1.1)",
                   "9.3(1.105)",
                   "9.3(1.50)",
                   "9.3(2)",
                   "9.3(2.100)",
                   "9.3(2.2)",
                   "9.3(2.243)",
                   "9.3(3)",
                   "9.3(3.1)",
                   "9.3(3.2)",
                   "9.3(3.5)",
                   "9.3(3.6)",
                   "9.3(3.9)",
                   "9.3(3.10)",
                   "9.3(3.11)",
                   "9.3(5)"),
  "9.4", make_list("9.4(1)",
                   "9.4(0.115)",
                   "9.4(1.1)",
                   "9.4(1.2)",
                   "9.4(1.3)",
                   "9.4(1.5)",
                   "9.4(2)",
                   "9.4(2.3)",
                   "9.4(3)",
                   "9.4(3.3)",
                   "9.4(3.4)",
                   "9.4(3.6)",
                   "9.4(3.8)",
                   "9.4(3.11)",
                   "9.4(3.12)"),
  "9.5", make_list("9.5(1)",
                   "9.5(2)",
                   "9.5(2.6)",
                   "9.5(2.10)",
                   "9.5(2.14)")
);

override = FALSE;
flag = FALSE;

majorversion = ereg_replace(pattern:"^([0-9.]+).*", string:version, replace:"\1");
vulnios = vulniosarray[majorversion];

foreach vulnver (vulnios)
{
  if (!check_asa_release(version:version, patched:vulnver) && !check_asa_release(version:vulnver, patched:version))
  {
    if (get_kb_item("Host/local_checks_enabled"))
      buf = cisco_command_kb_item("Host/Cisco/Config/show running-config", "show running-config");

    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^ *http server enable", string:buf))
        flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;

    if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the HTTP server is not enabled");
  }
}

if (flag || override)
  {
    security_report_cisco(
      port     : 0,
      override : override,
      severity : SECURITY_WARNING,
      version  : version,
      bug_id   : cbi,
      cmds     : make_list("show running-config")
      );
  }
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
