#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68930);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/10/06 23:50:20 $");

  script_cve_id("CVE-2013-1968", "CVE-2013-2112");
  script_bugtraq_id(60264, 60267);
  script_osvdb_id(93795, 93796);

  script_name(english:"Apache Subversion < 1.6.23 / 1.7.x < 1.7.10 Multiple Remote DoS");
  script_summary(english:"Checks Apache Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple denial
of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Apache Subversion Server is prior to 1.6.23
or 1.7.x prior to 1.7.10. It is, therefore, affected by multiple
remote denial of service vulnerabilities :

  - A flaw exists when handling specially crafted filenames
    that could result in corruption of the FSFS repository.
    A workaround exists to install a pre-commit hook that
    will prevent unsanitized filenames from being committed
    into the repository. (CVE-2013-1968)

  - A flaw exists in svnserve server where improperly
    handled aborted connection message are handled as
    critical errors. (CVE-2013-2112)");

  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-1968-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-2112-advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Subversion Server 1.6.23 / 1.7.10 / 1.8.0 or later
or apply the vendor patches or workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

if (
  ver_compare(ver:version, fix:'1.6.23', strict:FALSE) == -1 ||
  (ver_compare(ver:version, fix:'1.7.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.10', strict:FALSE) == -1)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Packaged with     : ' + provider +
             '\n  Installed version : ' + version +
             '\n  Fixed versions    : 1.6.23 / 1.7.10 / 1.8.0' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, provider + ' ' + appname, version, path);
