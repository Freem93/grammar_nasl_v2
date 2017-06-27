#TRUSTED 92b72b8cd5536a6d075eb7be599cd36a1a4c3c3200a01c50ed6c144bd633d04e7f69252cfc2813250ab208961e45f032f44e99993364951ed093325bfc375b6fd40f9d8ed17d0ff5aea530363ec2a81ee31470101fe8fdabc71b6c40a917c1064b55e40d836725991135fe83164ff312bf08920264e5aa319a6703834de16d9a9a3497ea4e3ef0b2d9227e912b01b7b101be783e3da89763e0e995a15eab286eb78c5d8ddc9a3db4d87094c6ed76d7359b66f1c7157e844c986918895da8546ea4e0b238c8ec2671c7fe395f95f4eda6599f2a6ff48338788cc066a27d865896fb224e7d5e96f3420803e78e6dcdfe323ea15470a12485e2fc8329d6688e0fffaab339ec460586af4f5c2f44aa8577238e5e209021e21b3caf0da3808c8fa11127824ca08fdc5b428b83665f5fa813822b3920963eec544e7ab5c15dda40922b7d41ea2a1fd99386b8de4d973f25a61763c909d6b91850e0236c7e1aebe0128cdfdccc4753281fdce936408bd50d96d4987a8fec8535ec4f9938d2cd27db37232a06a48cbad2ba3e8451f3acacddba468ba61b9a0d08899ecb0673df550f0e048d2c7c4fc6f2deafc36ef6963e663464c75d4be4856437f76d3fef20d00a78dbe9204ace0739b9a7e3d4bbbc0f94a6e32bb9a8c13f8ded43778719733b7f40569665e70607061231e81dba83e6fa3cb9f574d9337c17995b22539be0d5edca54
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94291);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/06");

  script_cve_id("CVE-2016-6431");
  script_bugtraq_id(93786);
  script_osvdb_id(146035);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz47295");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161019-asa-ca");

  script_name(english:"Cisco ASA Certificate Authority Enrollment Operation Packet Handling DoS (cisco-sa-20161019-asa-ca)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the
Certificate Authority (CA) feature due to improper handling of packets
during the enrollment operation. An unauthenticated, remote attacker
can exploit this, via a specially crafted enrollment request, to cause
the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161019-asa-ca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c05f684");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz47295");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20161019-asa-ca.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model !~ '^(1000)?v$'                 # reported by ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCuz47295';

if (version =~ "^8\.[012346][^0-9]")
  fixed_ver = "9.1(7.7)";

else if (version =~ "^9\.0[^0-9]" && check_asa_release(version:version, patched:"9.0(4.42)"))
  fixed_ver = "9.0(4.42)";

else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.7)"))
  fixed_ver = "9.1(7.7)";

else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.13)"))
  fixed_ver = "9.2(4.13)";

else if (version =~ "^9\.3[^0-9]" && check_asa_release(version:version,patched:"9.3(3.11)"))
  fixed_ver = "9.3(3.11)";

else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version,patched:"9.4(3.6)"))
  fixed_ver = "9.4(3.6)";

else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3)"))
  fixed_ver = "9.5(3)";

else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(1.5)"))
  fixed_ver = "9.6(1.5)";

else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show crypto ca server", "show crypto ca server");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"State *: *enabled", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the Certificate Authority feature is not enabled");
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
    cmds     : make_list("show crypto ca server")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
