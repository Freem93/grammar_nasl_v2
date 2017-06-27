#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1042.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93250);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-6313");

  script_name(english:"openSUSE Security Update : libgcrypt (openSUSE-2016-1042)");
  script_summary(english:"Check for the openSUSE-2016-1042 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libgcrypt fixes the following issues :

  - RNG prediction vulnerability (boo#994157, CVE-2016-6313)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994157"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-cavs-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-cavs-debuginfo-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-debugsource-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-devel-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-devel-debuginfo-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt20-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt20-debuginfo-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt20-hmac-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt20-32bit-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt20-debuginfo-32bit-1.6.1-8.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt20-hmac-32bit-1.6.1-8.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt-cavs / libgcrypt-cavs-debuginfo / libgcrypt-debugsource / etc");
}
