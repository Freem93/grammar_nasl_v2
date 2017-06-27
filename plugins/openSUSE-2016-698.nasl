#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-698.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91533);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-5104");

  script_name(english:"openSUSE Security Update : libimobiledevice / libusbmuxd (openSUSE-2016-698)");
  script_summary(english:"Check for the openSUSE-2016-698 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libimobiledevice, libusbmuxd fixes the following
issues :

  - Add libimobiledevice-CVE-2016-5104.patch: Make sure
    sockets only listen locally (CVE-2016-5104, boo#982014)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982014"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libimobiledevice / libusbmuxd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imobiledevice-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imobiledevice-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libimobiledevice6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libusbmuxd4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-imobiledevice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-imobiledevice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");
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

if ( rpm_check(release:"SUSE13.2", reference:"imobiledevice-tools-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"imobiledevice-tools-debuginfo-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"iproxy-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"iproxy-debuginfo-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libimobiledevice-debugsource-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libimobiledevice-devel-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libimobiledevice4-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libimobiledevice4-debuginfo-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libusbmuxd-debugsource-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libusbmuxd-devel-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libusbmuxd2-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libusbmuxd2-debuginfo-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-imobiledevice-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-imobiledevice-debuginfo-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libimobiledevice4-32bit-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libimobiledevice4-debuginfo-32bit-1.1.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libusbmuxd2-32bit-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libusbmuxd2-debuginfo-32bit-1.0.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"imobiledevice-tools-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"imobiledevice-tools-debuginfo-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"iproxy-1.0.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"iproxy-debuginfo-1.0.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libimobiledevice-debugsource-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libimobiledevice-devel-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libimobiledevice6-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libimobiledevice6-debuginfo-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libusbmuxd-debugsource-1.0.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libusbmuxd-devel-1.0.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libusbmuxd4-1.0.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libusbmuxd4-debuginfo-1.0.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-imobiledevice-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-imobiledevice-debuginfo-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libimobiledevice6-32bit-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libimobiledevice6-debuginfo-32bit-1.2.0-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libusbmuxd4-32bit-1.0.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libusbmuxd4-debuginfo-32bit-1.0.10-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imobiledevice-tools / imobiledevice-tools-debuginfo / etc");
}
