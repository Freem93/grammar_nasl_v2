#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71568);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2013-4262", "CVE-2013-4277");
  script_bugtraq_id(62266, 68965);
  script_osvdb_id(96930, 96931, 96932);

  script_name(english:"Apache Subversion 1.4.x - 1.7.12 / 1.8.x < 1.8.3 Multiple Symlink File Overwrite Vulnerabilities");
  script_summary(english:"Checks the Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
symlink overwrite vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Subversion Server installed on the remote host is prior
to version 1.8.3. It is, therefore, affected by multiple symlink file
overwrite vulnerabilities :

  - An error exists in the function 'handle_options' in the
    file 'svnwcsub.py' that could allow a local attacker to
    use a symlink attack to overwrite arbitrary files. Note
    that this issue only affects the 1.8.x branch.
    (CVE-2013-4262)

  - An error exists in the function 'write_pid_file' that
    could allow a local attacker to use a symlink attack to
    overwrite arbitrary files. (CVE-2013-4277)");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/security/CVE-2013-4262-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/security/CVE-2013-4277-advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Server 1.7.13 / 1.8.3 or later or apply the
vendor patches or workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("installed_sw/Subversion Server", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'Subversion Server';
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

path     = install['path'];
version  = install['version'];
provider = install['Packaged with'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected :
# 1.4.x through 1.7.x < 1.7.13
if(
  (ver_compare(ver:version, fix:'1.4.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.0') == -1) ||
  (ver_compare(ver:version, fix:'1.7.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.13') == -1) ||
  (ver_compare(ver:version, fix:'1.8.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.8.3') == -1)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Packaged with     : ' + provider +
             '\n  Installed version : ' + version +
             '\n  Fixed versions    : 1.7.13 / 1.8.3' +
             '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, provider + ' ' + appname, version, path);
