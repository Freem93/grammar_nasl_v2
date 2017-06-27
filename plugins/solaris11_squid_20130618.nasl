#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80773);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-5643", "CVE-2013-0189");

  script_name(english:"Oracle Solaris Third-Party Patch Update : squid (multiple_vulnerabilities_in_squid)");
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

  - Multiple memory leaks in tools/cachemgr.cc in
    cachemgr.cgi in Squid 2.x and 3.x before 3.1.22, 3.2.x
    before 3.2.4, and 3.3.x before 3.3.0.2 allow remote
    attackers to cause a denial of service (memory
    consumption) via (1) invalid Content-Length headers, (2)
    long POST requests, or (3) crafted authentication
    credentials. (CVE-2012-5643)

  - cachemgr.cgi in Squid 3.1.x and 3.2.x, possibly 3.1.22,
    3.2.4, and other versions, allows remote attackers to
    cause a denial of service (resource consumption) via a
    crafted request. NOTE: this issue is due to an incorrect
    fix for CVE-2012-5643, possibly involving an incorrect
    order of arguments or incorrect comparison.
    (CVE-2013-0189)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_squid
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?400aa275"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.8.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:squid");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^squid$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.8.0.4.0", sru:"SRU 11.1.8.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : squid\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "squid");
