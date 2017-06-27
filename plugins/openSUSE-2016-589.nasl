#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-589.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91206);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2016-4414");

  script_name(english:"openSUSE Security Update : quassel (openSUSE-2016-589)");
  script_summary(english:"Check for the openSUSE-2016-589 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for quassel fixes the following issues :

  - CVE-2016-4414: Denial of service vulnerability by
    unauthenticated clients (boo#978002)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978002"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quassel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-mono-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"quassel-base-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-client-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-client-debuginfo-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-core-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-core-debuginfo-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-debugsource-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-mono-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-mono-debuginfo-0.10.0-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-base-0.12.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-client-0.12.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-client-debuginfo-0.12.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-core-0.12.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-core-debuginfo-0.12.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-debugsource-0.12.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-mono-0.12.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"quassel-mono-debuginfo-0.12.2-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quassel-base / quassel-client / quassel-client-debuginfo / etc");
}
