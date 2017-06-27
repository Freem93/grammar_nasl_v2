#TRUSTED 905a939346a4bf29f8e4cc77a82320ba316ccc4672ce8b1071c58c7324731eb1b157ddeda916f330c27e03edd8dd5526309b91b664ab3050553b134bc7782d1d3b993813d146a3952b0096f41788835eb76891513adbcb9e3a0fedf08be2f17fd19725e7464d3c4060e65c8f5ce769fef66c88065d4e20413e431baf19b4b34b9a2ad49d5a4d2e1e94407898f08d1cf1d4f0561c68ecea16926d499216badd9574bb16d98d6702f37475572cb6693cb5d43e7bd0038cf8c60213123d15f785e575271f03551f61028175567d1eac004380cd6283f9055c8975c1ad93ccd859666fafd10ac66e88f7c08dd78f460c5b4c338b5cc115f340376f1828319259f504920d82de63f5059363a2872847e88b6217934069ab90f2016f81bdf10d5bba018bf0676f24ec0b074cb31b0a7a17e5319c7314fc0fcd04dabd01fd24bae67d147482f3ce92c11646dd8fe67e6a2cb21377fa7210d3829401e66d1c4eb4f5575801126bda8ac31333640236cde335b8e8945e9e5b4311cd8e0519d71e38c3f00b31a7cda2870e4f821e1f1b7c68235eeda2886dd52f03583ee901ebd6a3066f9aa3b969733cba68dd7798989e1364c5cef0b7dd1d99d7789169cb784f47d29edb81f3f3f1989511f9c69a59fe2c19bc9ef5f86fae418f5faf40daa5c4dba77c99a14755bebcaae6d537e3aa217574824eb7ba8124c18930eeade8eeb8008acecf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99400);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/15");

  script_cve_id("CVE-2017-3822");
  script_bugtraq_id(95944);
  script_osvdb_id(151287);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb86860");
  script_xref(name:"IAVB", value:"2017-B-0019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170201-fpw2");
  
  script_name(english:"Cisco Firepower Threat Defense Device Manager Web UI Request Handling Arbitrary Log Entry Injection (cisco-sa-20170201-fpw2)");
  script_summary(english:"Checks the version of Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by an arbitrary log entry injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Firepower Threat
Defense (FTD) software installed on the remote device is affected by
an arbitrary log entry injection vulnerability in the Firepower Device
Manager (FDM) due to improper validation of user-supplied input. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request to the web UI, to add arbitrary entires and false
alarms to the audit log.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170201-fpw2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8709094");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb86860.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");
include("obj.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

# Affected Models:
# 5506-X
# 5506W-X
# 5506H-X
# 5508-X
# 5512-X
# 5515-X
# 5516-X
# 5525-X
# 5545-X
# 5555-X
if (
  model !~ '^5506[WH]?-X' &&
  model !~ '^5508-X' &&
  model !~ '^551[256]-X' &&
  model !~ '^5525-X' &&
  model !~ '^5545-X' &&
  model !~ '^5555-X'
) audit(AUDIT_HOST_NOT, "an affect Cisco ASA product model");

flag = 0;
override = 0;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, "affected");

if (fdm_ver[1] =~ "^6\.1\.")
  flag= 1;

cmds = make_list();
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_managers", "show managers");
    if (check_cisco_result(buf))
    {
      # Vulnerable if managed locally
      if (preg(pattern:"^\s*Managed locally", multiline:TRUE, string:buf))
      {
        flag = 1;
        cmds = make_list(cmds, "show managers");
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : fdm_ver[1],
    bug_id   : "CSCvb86860",
    cmds     : cmds
  );
} else audit(AUDIT_HOST_NOT, "affected");
