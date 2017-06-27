#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80737);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-4248", "CVE-2013-6420", "CVE-2013-6712", "CVE-2014-1943", "CVE-2014-2270");

  script_name(english:"Oracle Solaris Third-Party Patch Update : php (cve_2013_4248_input_validation)");
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

  - The openssl_x509_parse function in openssl.c in the
    OpenSSL module in PHP before 5.4.18 and 5.5.x before
    5.5.2 does not properly handle a '\0' character in a
    domain name in the Subject Alternative Name field of an
    X.509 certificate, which allows man-in-the-middle
    attackers to spoof arbitrary SSL servers via a crafted
    certificate issued by a legitimate Certification
    Authority, a related issue to CVE-2009-2408.
    (CVE-2013-4248)

  - The asn1_time_to_time_t function in
    ext/openssl/openssl.c in PHP before 5.3.28, 5.4.x before
    5.4.23, and 5.5.x before 5.5.7 does not properly parse
    (1) notBefore and (2) notAfter timestamps in X.509
    certificates, which allows remote attackers to execute
    arbitrary code or cause a denial of service (memory
    corruption) via a crafted certificate that is not
    properly handled by the openssl_x509_parse function.
    (CVE-2013-6420)

  - The scan function in ext/date/lib/parse_iso_intervals.c
    in PHP through 5.5.6 does not properly restrict creation
    of DateInterval objects, which might allow remote
    attackers to cause a denial of service (heap-based
    buffer over-read) via a crafted interval specification.
    (CVE-2013-6712)

  - Fine Free file before 5.17 allows context-dependent
    attackers to cause a denial of service (infinite
    recursion, CPU consumption, and crash) via a crafted
    indirect offset value in the magic of a file.
    (CVE-2014-1943)

  - softmagic.c in file before 5.17 and libmagic allows
    context-dependent attackers to cause a denial of service
    (out-of-bounds memory access and crash) via crafted
    offsets in the softmagic of a PE executable.
    (CVE-2014-2270)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2013_4248_input_validation
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62b841d2"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_1943_resource_management
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01f1c299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2014_2270_buffer_errors"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_buffer_errors_vulnerabilities_in1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74a8aaaa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.19.6.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:php");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/22");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^php$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.19.0.6.0", sru:"SRU 11.1.19.6.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : php\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "php");
