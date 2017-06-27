#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80699);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2010-0295", "CVE-2013-1427", "CVE-2014-2469");

  script_name(english:"Oracle Solaris Third-Party Patch Update : lighttpd (cve_2014_2469_denial_of)");
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

  - lighttpd before 1.4.26, and 1.5.x, allocates a buffer
    for each read operation that occurs for a request, which
    allows remote attackers to cause a denial of service
    (memory consumption) by breaking a request into small
    pieces that are sent at a slow rate. (CVE-2010-0295)

  - The configuration file for the FastCGI PHP support for
    lighthttpd before 1.4.28 on Debian GNU/Linux creates a
    socket file with a predictable name in /tmp, which
    allows local users to hijack the PHP control socket and
    perform unauthorized actions such as forcing the use of
    a different version of PHP via a symlink attack or a
    race condition. (CVE-2013-1427)

  - Unspecified vulnerability in Lighthttpd in Oracle
    Solaris 11.1 allows attackers to cause a denial of
    service via unknown vectors. (CVE-2014-2469)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_2469_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_lighthttpd
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42c35650"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.17.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:lighttpd");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/21");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^lighttpd$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.17.0.5.0", sru:"SRU 11.1.17.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : lighttpd\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "lighttpd");
