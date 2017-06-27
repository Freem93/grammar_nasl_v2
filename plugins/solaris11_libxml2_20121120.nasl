#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80688);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/26 05:42:54 $");

  script_cve_id("CVE-2011-0216", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3102", "CVE-2011-3905", "CVE-2011-3919", "CVE-2012-0841");

  script_name(english:"Oracle Solaris Third-Party Patch Update : libxml2 (cve_2011_0216_denial_of)");
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

  - Off-by-one error in libxml in Apple Safari before 5.0.6
    allows remote attackers to execute arbitrary code or
    cause a denial of service (heap-based buffer overflow
    and application crash) via a crafted web site.
    (CVE-2011-0216)

  - Double free vulnerability in libxml2, as used in Google
    Chrome before 13.0.782.215, allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via a crafted XPath expression.
    (CVE-2011-2821)

  - Double free vulnerability in libxml2, as used in Google
    Chrome before 14.0.835.163, allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via vectors related to XPath handling.
    (CVE-2011-2834)

  - Off-by-one error in libxml2, as used in Google Chrome
    before 19.0.1084.46 and other products, allows remote
    attackers to cause a denial of service (out-of-bounds
    write) or possibly have unspecified other impact via
    unknown vectors. (CVE-2011-3102)

  - libxml2, as used in Google Chrome before 16.0.912.63,
    allows remote attackers to cause a denial of service
    (out-of-bounds read) via unspecified vectors.
    (CVE-2011-3905)

  - Heap-based buffer overflow in libxml2, as used in Google
    Chrome before 16.0.912.75, allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via unknown vectors. (CVE-2011-3919)

  - libxml2 before 2.8.0 computes hash values without
    restricting the ability to trigger hash collisions
    predictably, which allows context-dependent attackers to
    cause a denial of service (CPU consumption) via crafted
    XML data. (CVE-2012-0841)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2011_0216_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2011_3102_numeric_errors
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?944e490b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2012_0841_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_denial_of_service_dos2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d0b22ff"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_denial_of_service_dos3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fc111b5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 10.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:libxml2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^libxml2$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.10.0.5.0", sru:"SRU 10.5a") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : libxml2\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "libxml2");
