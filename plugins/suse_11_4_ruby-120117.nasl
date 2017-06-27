#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ruby-5660.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76015);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:19:38 $");

  script_cve_id("CVE-2011-2686", "CVE-2011-2705", "CVE-2011-3009", "CVE-2011-4815");
  script_osvdb_id(74647, 74841, 78118);

  script_name(english:"openSUSE Security Update : ruby (openSUSE-SU-2012:0228-1)");
  script_summary(english:"Check for the ruby-5660 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ruby provides 1.8.7p357, which contains many stability
fixes and bug fixes, which are fully compatible with the previous
version. You can review the detailed list here :

http://svn.ruby-lang.org/repos/ruby/tags/v1_8_7_357/ChangeLog

The particularly noteworthy fixes are :

  - Hash functions are now using a randomized seed to avoid
    algorithmic complexity attacks (CVE-2011-4815). For this
    OpenSSL::Random.seed at the SecureRandom.random_bytes is
    used if available.

  - mkconfig.rb: fix for continued lines.

  - Fix Infinity to be greater than any bignum number.

  - initialize store->ex_data.sk.

  - some IPv6 related fixes

  - zlib fixes

  - reinitialize PRNG when forking children
    (CVE-2011-2686/CVE-2011-3009)

  - securerandom fixes (CVE-2011-2705)

  - uri route_to fixes

  - fix race condition with variables and autoload"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-02/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.ruby-lang.org/repos/ruby/tags/v1_8_7_357/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739122"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-test-suite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"ruby-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-debuginfo-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-debugsource-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-devel-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-doc-html-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-doc-ri-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-examples-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-test-suite-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-tk-1.8.7.p357-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"ruby-tk-debuginfo-1.8.7.p357-0.2.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ruby");
}
