#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80757);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-4164", "CVE-2013-4287", "CVE-2013-4363");

  script_name(english:"Oracle Solaris Third-Party Patch Update : ruby (multiple_vulnerabilities_in_ruby1)");
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

  - Heap-based buffer overflow in Ruby 1.8, 1.9 before
    1.9.3-p484, 2.0 before 2.0.0-p353, 2.1 before 2.1.0
    preview2, and trunk before revision 43780 allows
    context-dependent attackers to cause a denial of service
    (segmentation fault) and possibly execute arbitrary code
    via a string that is converted to a floating point
    value, as demonstrated using (1) the to_f method or (2)
    JSON.parse. (CVE-2013-4164)

  - Algorithmic complexity vulnerability in
    Gem::Version::VERSION_PATTERN in lib/
    rubygems/version.rb in RubyGems before 1.8.23.1, 1.8.24
    through 1.8.25, 2.0.x before 2.0.8, and 2.1.x before
    2.1.0, as used in Ruby 1.9.0 through 2.0.0p247, allows
    remote attackers to cause a denial of service (CPU
    consumption) via a crafted gem version that triggers a
    large amount of backtracking in a regular expression.
    (CVE-2013-4287)

  - Algorithmic complexity vulnerability in
    Gem::Version::ANCHORED_VERSION_PATTERN in
    lib/rubygems/version.rb in RubyGems before 1.8.23.2,
    1.8.24 through 1.8.26, 2.0.x before 2.0.10, and 2.1.x
    before 2.1.5, as used in Ruby 1.9.0 through 2.0.0p247,
    allows remote attackers to cause a denial of service
    (CPU consumption) via a crafted gem version that
    triggers a large amount of backtracking in a regular
    expression. NOTE: this issue is due to an incomplete fix
    for CVE-2013-4287. (CVE-2013-4363)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_ruby1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60c5d0a7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.15.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:ruby");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
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

if (solaris_check_release(release:"0.5.11-0.175.1.15.0.4.0", sru:"SRU 11.1.15.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : ruby\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "ruby");
