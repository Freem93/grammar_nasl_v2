#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97417);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/01 14:52:05 $");

  script_cve_id("CVE-2017-3902");
  script_osvdb_id(151967);
  script_xref(name:"MCAFEE-SB", value:"SB10184");

  script_name(english:"McAfee ePolicy Orchestrator 5.1.x < 5.1.3 HF1110787 Computer Management Services XSS (SB10184)");
  script_summary(english:"Checks the version of ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application installed on the remote Windows
host is affected by a reflected cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee ePolicy Orchestrator (ePO) installed on the
remote Windows host is 5.1.x prior to 5.1.3 hotfix 1110787. It is,
therefore, affected by a reflected cross-site scripting (XSS)
vulnerability in the web user interface (UI), specifically within the
ePO computer management services, due to a failure to properly
validate user-supplied input to unspecified  parameters. An
authenticated, remote attacker can exploit this vulnerability, by
convincing a user into requesting a specially crafted URL, to execute
arbitrary script code in the user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.1.3 hotfix 1110787 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated","installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");
include("bsal.inc");
include("byte_func.inc");
include("zip.inc");

app_name = "McAfee ePO";
install = get_single_install(
  app_name : app_name,
  exit_if_unknown_ver : TRUE
);
dir = install['path'];
build_ver = install['version'];
report = NULL;

# Only version 5.1.x branch is affected.
# We need the build numbers to construct the Hotfix path later
# to prevent it from auditing out during the ComputerMgmt.jar version
# check:
# https://kc.mcafee.com/corporate/index?page=content&id=KB61057
if(build_ver =~ "^5\.1\.0\..*$")
{
  hf_jar_fix_ver = '5.1.3.266';
  req_build_ver = '5.1.0.509';
  hf_report = 'Upgrade to ePO 5.1.3 and then apply hotfix EPO5xHF1110787.zip.';
}
else if(build_ver =~ "^5\.1\.1\..*$")
{
  hf_jar_fix_ver = '5.1.3.266';
  req_build_ver = '5.1.1.357';
  hf_report = 'Upgrade to ePO 5.1.3 and then apply hotfix EPO5xHF1110787.zip.';
}
else if(build_ver =~ "^5\.1\.2\..*$")
{
  hf_jar_fix_ver = '5.1.3.266';
  req_build_ver = '5.1.2.348';
  hf_report = 'Upgrade to ePO 5.1.3 and then apply hotfix EPO5xHF1110787.zip.';
}
else if(build_ver =~ "^5\.1\.3\..*$")
{
  hf_jar_fix_ver = '5.1.3.266';
  req_build_ver = '5.1.3.188';
  hf_report = 'Apply hotfix EPO5xHF1110787.zip.';
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, build_ver, dir);

# Based on the required build number version, extract the "Specification-Version"
# from the ComputerMgmt.jar file's META-INF\MANIFEST.MF if it exists.

# Get one of the modified JAR files.
hf_jar_path = "\server\extensions\installed\ComputerMgmt\" + req_build_ver + "\webapp\WEB-INF\lib\ComputerMgmt.jar";
jar_path = hotfix_append_path(path:dir, value:hf_jar_path);
jar_contents = hotfix_get_file_contents(jar_path);
hotfix_handle_error(error_code:jar_contents['error'], file:jar_path, exit_on_fail:TRUE);
hotfix_check_fversion_end();

# Get the version from the manifest.
manifest = zip_parse(blob:jar_contents['data'], "META-INF/MANIFEST.MF");
match = eregmatch(string:manifest, pattern:"Specification-Version: ((\d+\.?)+)");
if (isnull(match)) exit(1, "Failed to parse specification version from manifest.");
jar_ver = match[1];

port = kb_smb_transport();

# Compare ComputerMgmt.jar's reported file version to the version the patches replace.
if(ver_compare(ver:jar_ver, fix:hf_jar_fix_ver, strict:FALSE) < 0)
{
  report =
    '\n Application : McAfee ePolicy Orchestrator ' + build_ver +
    '\n Path        : ' + jar_path +
    '\n Version     : ' + jar_ver +
    '\n Fix version : ' + hf_jar_fix_ver +
    '\n Fix         : ' + hf_report +
    '\n';
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report, xss:TRUE);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name + "'s ComputerMgmt.jar", jar_ver);
