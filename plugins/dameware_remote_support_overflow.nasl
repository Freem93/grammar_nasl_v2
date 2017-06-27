#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72742);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/25 17:03:06 $");

  script_cve_id("CVE-2013-3249");
  script_bugtraq_id(61453);
  script_osvdb_id(95658);

  script_name(english:"DameWare Remote Support < 9 Hotfix 2 / 10 Hotfix 2 DWExporter.exe Buffer Overflow");
  script_summary(english:"Checks timestamp of DWExporter.exe");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of DameWare Remote Support
prior to 9.0.1 / 10.0.0 Hotfix 2. It is, therefore, affected by a
buffer overflow vulnerability due to a flaw in DWExporter.exe. An
attacker could potentially exploit this vulnerability to remotely
execute arbitrary code.");
  script_set_attribute(attribute:"solution", value:"Upgrade to 9.0.1 Hotfix 2 / 10.0.0 Hotfix 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dameware:remote_support");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_dependencies("dameware_remote_support_installed.nbin");
  script_require_keys("SMB/dameware_remote_support/version", "SMB/dameware_remote_support/path");
  script_require_ports(139, 445);

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("datetime.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

app_name = 'DameWare Remote Support';
version = get_kb_item_or_exit("SMB/dameware_remote_support/version");
install_path = get_kb_item_or_exit("SMB/dameware_remote_support/path");

# If version isn't 9 or 10, then the install isn't vulnerable.
if (version =~ "^9\..*$") fix = 1368182345;
else if (version =~ "^10\..*$") fix = 1368188020;
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

# Interim Fix consists of a patched EXE, so look at the timestamp.
file_path = hotfix_append_path(path:install_path, value:"DWExporter.exe");
file_timestamp = hotfix_get_timestamp(path:file_path);

hotfix_handle_error(error_code:file_timestamp['error'],
                    file:file_path,
                    appname:app_name,
                    exit_on_fail:TRUE);

hotfix_check_fversion_end();

timestamp = file_timestamp['value'];

if (timestamp < fix)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  File              : ' + file_path +
      '\n  File timestamp    : ' + strftime(timestamp) +
      '\n  Fixed timestamp   : ' + strftime(fix) +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);
