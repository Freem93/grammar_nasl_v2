#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80705);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2008-4098", "CVE-2008-7247", "CVE-2010-1626", "CVE-2013-1861");

  script_name(english:"Oracle Solaris Third-Party Patch Update : mysql (multiple_vulnerabilities_in_mysql)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - MySQL before 5.0.67 allows local users to bypass certain
    privilege checks by calling CREATE TABLE on a MyISAM
    table with modified (1) DATA DIRECTORY or (2) INDEX
    DIRECTORY arguments that are originally associated with
    pathnames without symlinks, and that can point to tables
    created at a future time at which a pathname is modified
    to contain a symlink to a subdirectory of the MySQL home
    data directory. NOTE: this vulnerability exists because
    of an incomplete fix for CVE-2008-4097. (CVE-2008-4098)

  - sql/sql_table.cc in MySQL 5.0.x through 5.0.88, 5.1.x
    through 5.1.41, and 6.0 before 6.0.9-alpha, when the
    data home directory contains a symlink to a different
    filesystem, allows remote authenticated users to bypass
    intended access restrictions by calling CREATE TABLE
    with a (1) DATA DIRECTORY or (2) INDEX DIRECTORY
    argument referring to a subdirectory that requires
    following this symlink. (CVE-2008-7247)

  - MySQL before 5.1.46 allows local users to delete the
    data and index files of another user's MyISAM table via
    a symlink attack in conjunction with the DROP TABLE
    command, a different vulnerability than CVE-2008-4098
    and CVE-2008-7247. (CVE-2010-1626)

  - MariaDB 5.5.x before 5.5.30, 5.3.x before 5.3.13, 5.2.x
    before 5.2.15, and 5.1.x before 5.1.68, and Oracle MySQL
    5.1.69 and earlier, 5.5.31 and earlier, and 5.6.11 and
    earlier allows remote attackers to cause a denial of
    service (crash) via a crafted geometry feature that
    specifies a large number of points, which is not
    properly handled when processing the binary
    representation of this feature, related to a numeric
    calculation error. (CVE-2013-1861)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_mysql
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ad04fd7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.10.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:mysql");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^mysql$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.10.0.5.0", sru:"SRU 11.1.10.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : mysql\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "mysql");
