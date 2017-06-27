#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-435.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99208);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2015-7551", "CVE-2016-2339");

  script_name(english:"openSUSE Security Update : ruby2.2 / ruby2.3 (openSUSE-2017-435)");
  script_summary(english:"Check for the openSUSE-2017-435 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ruby2.2, ruby2.3 fixes the following issues :

Security issues fixed :

  - CVE-2016-2339: heap overflow vulnerability in the
    Fiddle::Function.new'initialize' (boo#1018808)

  - CVE-2015-7551: Unsafe tainted string usage in Fiddle and
    DL (boo#959495)

Detailed ChangeLog :

- http://svn.ruby-lang.org/repos/ruby/tags/v2_2_6/ChangeLog

- http://svn.ruby-lang.org/repos/ruby/tags/v2_3_3/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_2_6/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_3_3/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959495"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ruby2.2 / ruby2.3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_2-2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_2-2_2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_3-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_3-2_3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.2-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libruby2_2-2_2-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libruby2_2-2_2-debuginfo-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-debuginfo-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-debugsource-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-devel-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-devel-extra-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-doc-ri-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-stdlib-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-stdlib-debuginfo-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-tk-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.2-tk-debuginfo-2.2.6-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libruby2_2-2_2-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libruby2_2-2_2-debuginfo-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libruby2_3-2_3-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libruby2_3-2_3-debuginfo-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-debuginfo-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-debugsource-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-devel-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-devel-extra-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-doc-ri-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-stdlib-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-stdlib-debuginfo-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-tk-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.2-tk-debuginfo-2.2.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-debuginfo-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-debugsource-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-devel-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-devel-extra-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-doc-ri-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-stdlib-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-stdlib-debuginfo-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-tk-2.3.3-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.3-tk-debuginfo-2.3.3-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby2_2-2_2 / libruby2_2-2_2-debuginfo / ruby2.2 / etc");
}
