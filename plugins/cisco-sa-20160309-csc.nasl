#TRUSTED 0d255e7738662b28f4e6ce44549d9ad2a70e06808d4fa029b52ab86834e982a7e9f1a078f7caed18cfcbca24f0583e2ac852eda591d84bb429dae67f5af038c48ce97d4f6e8b4c12f9a4c0800f6db6e2a1f1e668d1cc7b2299fc47273518c92bb3fa682410fa2a5410baf7fd0a9a4b4faa13c665370c175012c16e5b69417e176aea5d1e11b95335044aa070561e02e303e5b4f9edde722d05eaef34c85a92dbe547c1732ac19ee2a25a84beed3533efc0332aeb41b1462f7a9e36626e2ec3d7c5885890534bfed60ed984eb4bc30695fbee76865d18c8b3e0945e35ef041549107b186e7c32b9fabb05d9d72a5569ee9f67c79f3811db52d16afc00bcdde2c65c631aed82b12b1789007dc545afc2ced1ae460aac38c22df4e75b85cdea430c6ec376e064d596d06fbba9eb2d5f2527eeee82c852486c1eb2568957714b9170c6ecb7846474584a88cf271923ef547668301643d3636d28176319aa1eac1fefc855fb02d437ee5ad09ef1b15916b5df7e7b04b47fc90880b524e976f834c9fba3a061107c7223e3d217985b1901e5795f3e7177f3a742ecb06466be3c46a38e347fada07ca42f3c7e935d64b10eeb6a3e307c407a333a6c4aca8767a29816e6fc83cd971f41b98e2698c386812ace198676c9fdc5bc6638817b3c5fb223a391e88facb422e4117ceffb1208762c7a22a864f5bb48fb113908305b135d6dff8c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90066);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2016-1312");
  script_bugtraq_id(84281);
  script_osvdb_id(135653);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue76147");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160309-csc");

  script_name(english:"Cisco ASA Content Security and Control Security Services Module (CSC-SSM) DoS (cisco-sa-20160309-csc)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch. It is, therefore, affected by a denial
of service vulnerability in the Content Security and Control Security
Services Module (CSC-SSM) due to improper handling of HTTPS packets.
An unauthenticated, remote attacker can exploit this, by sending a 
high rate of HTTPS packets, to exhaust available memory resources,
resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160309-csc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?884fa710");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCue76147.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

model = get_kb_item_or_exit('Host/Cisco/ASA/model');
if (model !~ '^55[0-9]{2}($|[^0-9])')
  audit(AUDIT_HOST_NOT, "Cisco ASA 5500");

buf = cisco_command_kb_item("Host/Cisco/Config/show_module",
                            "show module");
override = FALSE;
csc_ver = NULL;

if (check_cisco_result(buf))
{
  if (!ereg(multiline:TRUE, pattern:"CSC SSM", string:buf))
    exit(0, "CSC SSM Module not detected.");

  extract = pregmatch(multiline:TRUE, pattern:"^.*CSC SSM\s+(Up|Down)\s+([0-9\.]+).*$", string:buf);
  if (!empty_or_null(extract))
    csc_ver = extract[2];
  else
    exit(1, "Unable to obtain CSC SSM Module version.");
}
else if (cisco_needs_enable(buf))
  override = TRUE;

fix = "6.6.1164.0";

if (empty_or_null(csc_ver))
  audit(AUDIT_UNKNOWN_APP_VER, "Cisco ASA " + model);

if (csc_ver =~ "^6\.6\." &&
    ver_compare(ver:csc_ver, fix:fix, strict:FALSE) < 0 &&
    csc_ver !~ "^6\.6\.1157\.")
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : csc_ver,
    fix      : fix,
    bug_id   : "CSCue76147",
    cmds     : make_list("show module")
  );
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA " + model + ", CSC SSM", csc_ver);
