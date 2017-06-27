#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80755);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-1005", "CVE-2012-4481", "CVE-2013-4073");

  script_name(english:"Oracle Solaris Third-Party Patch Update : ruby (cve_2013_4073_cryptographic_issues)");
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

  - The safe-level feature in Ruby 1.8.6 through 1.8.6-420,
    1.8.7 through 1.8.7-330, and 1.8.8dev allows
    context-dependent attackers to modify strings via the
    Exception#to_s method, as demonstrated by changing an
    intended pathname. (CVE-2011-1005)

  - The safe-level feature in Ruby 1.8.7 allows
    context-dependent attackers to modify strings via the
    NameError#to_s method when operating on Ruby objects.
    NOTE: this issue is due to an incomplete fix for
    CVE-2011-1005. (CVE-2012-4481)

  - The OpenSSL::SSL.verify_certificate_identity function in
    lib/openssl/ssl.rb in Ruby 1.8 before 1.8.7-p374, 1.9
    before 1.9.3-p448, and 2.0 before 2.0.0-p247 does not
    properly handle a '\0' character in a domain name in the
    Subject Alternative Name field of an X.509 certificate,
    which allows man-in-the-middle attackers to spoof
    arbitrary SSL servers via a crafted certificate issued
    by a legitimate Certification Authority, a related issue
    to CVE-2009-2408. (CVE-2013-4073)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2013_4073_cryptographic_issues
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d657282"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_ruby
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca501082"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.11.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:ruby");

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

if (empty_or_null(egrep(string:pkg_list, pattern:"^ruby$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.11.0.4.0", sru:"SRU 11.1.11.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : ruby\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "ruby");
