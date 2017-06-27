#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66474);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/10/06 23:50:20 $");

  script_cve_id(
    "CVE-2013-1845",
    "CVE-2013-1846",
    "CVE-2013-1847",
    "CVE-2013-1849",
    "CVE-2013-1884"
  );
  script_bugtraq_id(58323, 58895, 58896, 58897, 58898);
  script_osvdb_id(92090, 92091, 92092, 92093, 92094);

  script_name(english:"Apache Subversion < 1.6.21 / 1.7.x < 1.7.9 Multiple DoS");
  script_summary(english:"Checks Apache Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple denial
of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Subversion Server installed on the remote host
is prior to 1.6.21 or 1.7.x prior to 1.7.9. It is, therefore, affected
by multiple denial of service (DoS) vulnerabilities in the
'mod_dav_svn' Apache HTTPD server module :

  - A flaw exists in 'mod_dav_svn' that is triggered when
    handling node properties. (CVE-2013-1845)

  - A NULL pointer dereference exists in the 'mod_dav_svn'
    module, triggered during the handling of a crafted Log
    REPORT request, URL lock request, LOCK request against
    non-existent URL, or URL PROPFIND request.
    (CVE-2013-1846, CVE-2013-1847, CVE-2013-1849)

  - A NULL pointer dereference exists in the 'mod_dav_svn'
    module, triggered during the handling of a crafted Log
    REPORT request. This flaw reportedly affects Apache
    Subversion 1.7.x only.  (CVE-2013-1884)");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-1845-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-1846-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-1847-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-1849-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-1884-advisory.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Subversion Server 1.6.21 / 1.7.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");

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
  ver_compare(ver:version, fix:'1.6.21', strict:FALSE) == -1 ||
  (ver_compare(ver:version, fix:'1.7.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.9', strict:FALSE) == -1)
)
{
  port     = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Packaged with     : ' + provider +
             '\n  Installed version : ' + version +
             '\n  Fixed versions    : 1.6.21 / 1.7.9' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, provider + ' ' + appname, version, path);
