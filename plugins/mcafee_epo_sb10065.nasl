#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72729);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2014-2205");
  script_bugtraq_id(65771);
  script_osvdb_id(103717);
  script_xref(name:"MCAFEE-SB", value:"SB10065");

  script_name(english:"McAfee ePolicy Orchestrator < 4.6.7 HF940148 XML Entity Injection (SB10065)");
  script_summary(english:"Checks version of ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an XML entity injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of McAfee ePolicy
Orchestrator (ePO) prior to 4.6.7 hotfix 940148. It is, therefore,
affected by an XML entity injection vulnerability due to a failure to
properly sanitize user-supplied input. An authenticated, remote
attacker with permission to add new dashboards can exploit this
vulnerability to access arbitrary server side system files.");
  # https://www.redteam-pentesting.de/en/advisories/rt-sa-2014-001/-mcafee-epolicy-orchestrator-xml-external-entity-expansion-in-dashboard
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8b4a72e");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10065");
  script_set_attribute(attribute:"solution", value:
 "Upgrade to McAfee ePO version 4.6.7 hotfix 940148 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("bsal.inc");
include("byte_func.inc");
include("zip.inc");

app_name = "McAfee ePolicy Orchestrator";
version = get_kb_item_or_exit("SMB/mcafee_epo/ver");
install_path = get_kb_item_or_exit("SMB/mcafee_epo/Path");

fix = '4.6.7';
hotfix = 'Hotfix 940148';
hotfix_timestamp = '201401292145';
report = NULL;

# Only version 4.6.x  and 4.5.x are affected (4.5 is EOL).
if (version !~ "^4\.[56]\..*$") audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

# If version is prior to 4.6.7, report as vulnerable.
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Path              : ' + install_path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + ' ' + hotfix +
    '\n';
}
# Otherwise, check for hotfix.
else
{
  # Get one of the modified JAR files.
  jar_path = hotfix_append_path(path:install_path, value:"Server\common\lib\orion-core-common.jar");
  jar_contents = hotfix_get_file_contents(jar_path);
  hotfix_handle_error(error_code:jar_contents['error'], file:jar_path, appname:app_name, exit_on_fail:TRUE);
  hotfix_check_fversion_end();

  # Get the version from the manifest.
  manifest = zip_parse(blob:jar_contents['data'], "META-INF/MANIFEST.MF");
  match = eregmatch(string:manifest, pattern:"Implementation-Version: (\d+)");
  if (isnull(match)) exit(1, "Failed to parse implementation version from manifest.");

  timestamp = match[1];

  if (timestamp < hotfix_timestamp)
  {
    report =
      '\n  Path                 : ' + install_path +
      '\n  Installed version    : ' + version +
      '\n' +
      '\n  Based on its build date, the following file needs to be updated :' +
      '\n    ' + jar_path +
      '\n' +
      '\n  Installed build date : ' + timestamp +
      '\n  Fixed build date     : ' + hotfix_timestamp +
      '\n' +
      '\n' + 'Install ' + fix + ' ' + hotfix + ' to correct the issue.' +
      '\n';
  }
  else audit(AUDIT_PATCH_INSTALLED, hotfix);
}

port = kb_smb_transport();
if (report_verbosity > 0) security_warning(extra:report, port:port);
else security_warning(port);
