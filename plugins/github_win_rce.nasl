#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80202);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2014-9390");
  script_bugtraq_id(71732);
  script_osvdb_id(116041);

  script_name(english:"GitHub for Windows < 2.6.5 .git/config Command Execution");
  script_summary(english:"Checks the version of GitHub.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of GitHub for Windows installed on the remote host is
prior to 2.6.5. It is, therefore, affected by a command execution
vulnerability when processing specially crafted git trees in a
case-insensitive or case-normalizing file system. A remote attacker,
using a specially crafted git tree, can overwrite a user's
'.git/config' file when the user clones or checks out a repository,
allowing arbitrary command execution.");
  # https://github.com/blog/1938-vulnerability-announced-update-your-git-clients
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad68bb83");
  script_set_attribute(attribute:"see_also", value:"https://windows.github.com/release-notes.html");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.linux.kernel/1853266");
  # http://git-blame.blogspot.com/2014/12/git-1856-195-205-214-and-221-and.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afc47628");
  script_set_attribute(attribute:"solution", value:"Upgrade to GitHub for Windows 2.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git and Mercurial HTTP Server For CVE-2014-9390');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:github:github");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git:git");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("github_win_installed.nbin");
  script_require_keys("installed_sw/GitHub for Windows");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "GitHub for Windows";

install = get_single_install(app_name:appname);

version = install['version'];
path    = install['path'];

if (ver_compare(ver:version, fix:'2.6.5', strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.6.5.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
