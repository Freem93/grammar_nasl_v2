#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78068);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2014-3522", "CVE-2014-3528");
  script_bugtraq_id(68995, 69237);
  script_osvdb_id(109748, 109996);

  script_name(english:"Apache Subversion 1.0.x - 1.7.17 / 1.8.x < 1.8.10 Multiple Vulnerabilities");
  script_summary(english:"Checks the Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Subversion Server installed on the remote host is
version 1.x.x prior to 1.7.18 or 1.8.x prior to 1.8.10. It is,
therefore, affected by the following vulnerabilities :

  - A flaw exists in the Serf RA layer. This flaw causes
    wildcards for HTTPS connections to be improperly
    evaluated, which may result in the application
    accepting certificates that are not matched against the
    proper hostname. This may allow a remote
    man-in-the-middle attacker to intercept traffic and
    spoof valid sessions. (CVE-2014-3522)

  - An MD5 hash of the URL and authentication realm are
    used to store cached credentials, which may allow
    remote attackers to obtain these credentials via a
    specially crafted authentication realm. (CVE-2014-3528)");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2014-3522-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2014-3528-advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Server 1.7.18 / 1.8.10 or later, or apply the
vendor-supplied patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
# 1.0.0 through 1.7.17
# 1.8.0 through 1.8.9
if (
  (ver_compare(ver:version, fix:'1.0.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.17', strict:FALSE) <= 0) ||
  (ver_compare(ver:version, fix:'1.8.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.8.9', strict:FALSE) <= 0)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Packaged with     : ' + provider +
             '\n  Installed version : ' + version +
             '\n  Fixed versions    : 1/7/18 / 1.8.10' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, provider + ' ' + appname, version, path);
