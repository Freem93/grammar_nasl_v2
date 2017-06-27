#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-452.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99277);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/11 16:24:59 $");

  script_cve_id("CVE-2017-6507");

  script_name(english:"openSUSE Security Update : apparmor (openSUSE-2017-452)");
  script_summary(english:"Check for the openSUSE-2017-452 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apparmor fixes the following issues :

These security issues were fixed :

  - CVE-2017-6507: Preserve unknown profiles when reloading
    apparmor.service (lp#1668892, boo#1029696)

  - boo#1017260: Migration to apparmor.service accidentally
    disable AppArmor. Note: This will re-enable AppArmor if
    it was disabled by the last update. You'll need to
    'rcapparmor reload' to actually load the profiles, and
    then check aa-status for programs that need to be
    restarted to apply the profiles.

These non-security issues were fixed :

  - Fixed crash in aa-logprof on specific change_hat events

  - boo#1016259: Added var.mount dependeny to
    apparmor.service

The aa-remove-unknown utility was added to unload unknown profiles
(lp#1668892)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029696"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apparmor packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-abstractions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-utils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");
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

if ( rpm_check(release:"SUSE42.1", reference:"apache2-mod_apparmor-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apache2-mod_apparmor-debuginfo-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-abstractions-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-debugsource-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-parser-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-parser-debuginfo-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-parser-lang-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-profiles-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-utils-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"apparmor-utils-lang-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libapparmor-devel-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libapparmor1-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libapparmor1-debuginfo-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pam_apparmor-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pam_apparmor-debuginfo-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-apparmor-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-apparmor-debuginfo-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-apparmor-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-apparmor-debuginfo-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby-apparmor-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby-apparmor-debuginfo-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libapparmor1-32bit-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libapparmor1-debuginfo-32bit-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"pam_apparmor-32bit-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"pam_apparmor-debuginfo-32bit-2.10.2-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apache2-mod_apparmor-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apache2-mod_apparmor-debuginfo-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-abstractions-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-debugsource-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-parser-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-parser-debuginfo-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-parser-lang-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-profiles-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-utils-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apparmor-utils-lang-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapparmor-devel-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapparmor1-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapparmor1-debuginfo-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pam_apparmor-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pam_apparmor-debuginfo-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-apparmor-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-apparmor-debuginfo-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python3-apparmor-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python3-apparmor-debuginfo-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby-apparmor-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby-apparmor-debuginfo-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libapparmor1-32bit-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libapparmor1-debuginfo-32bit-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"pam_apparmor-32bit-2.10.2-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"pam_apparmor-debuginfo-32bit-2.10.2-12.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_apparmor / apache2-mod_apparmor-debuginfo / etc");
}
