#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80630);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-1619", "CVE-2013-2116");

  script_name(english:"Oracle Solaris Third-Party Patch Update : gnutls (cve_2013_1619_cryptographic_issues)");
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

  - The TLS implementation in GnuTLS before 2.12.23, 3.0.x
    before 3.0.28, and 3.1.x before 3.1.7 does not properly
    consider timing side-channel attacks on a noncompliant
    MAC check operation during the processing of malformed
    CBC padding, which allows remote attackers to conduct
    distinguishing attacks and plaintext-recovery attacks
    via statistical analysis of timing data for crafted
    packets, a related issue to CVE-2013-0169.
    (CVE-2013-1619)

  - The _gnutls_ciphertext2compressed function in
    lib/gnutls_cipher.c in GnuTLS 2.12.23 allows remote
    attackers to cause a denial of service (buffer over-read
    and crash) via a crafted padding length. NOTE: this
    might be due to an incorrect fix for CVE-2013-0169.
    (CVE-2013-2116)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2013_1619_cryptographic_issues
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f196156"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2013_2116_input_validation
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b40ccb3a"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.11.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:gnutls");

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

if (empty_or_null(egrep(string:pkg_list, pattern:"^gnutls$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.11.0.4.0", sru:"SRU 11.1.11.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : gnutls\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "gnutls");
