#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-150.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96788);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/26 14:48:47 $");

  script_cve_id("CVE-2016-10156");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2017-150)");
  script_summary(english:"Check for the openSUSE-2017-150 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

This security issue was fixed :

  - CVE-2016-10156: Fix permissions set on permanent timer
    timestamp files, preventing local unprivileged users
    from escalating privileges (bsc#1020601).

These non-security issues were fixed :

  - Fix permission set on /var/lib/systemd/linger/*

  - install: follow config_path symlink (#3362)

  - install: fix disable when /etc/systemd/system is a
    symlink (bsc#1014560)

  - run: make --slice= work in conjunction with --scope
    (bsc#1014566)

  - core: don't dispatch load queue when setting Slice= for
    transient units

  - systemctl: remove duplicate entries showed by
    list-dependencies (#5049) (bsc#1012266)

  - rule: don't automatically online standby memory on s390x
    (bsc#997682)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997682"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-mini-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-mini-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-devel-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-mini-devel-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-mini1-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-mini1-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev1-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev1-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-myhostname-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-myhostname-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-mymachines-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-mymachines-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-bash-completion-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-debugsource-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-devel-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-logger-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-bash-completion-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-debugsource-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-devel-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-sysvinit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-sysvinit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-mini-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-mini-debuginfo-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsystemd0-32bit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libudev1-32bit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"nss-myhostname-32bit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"systemd-32bit-228-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-22.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsystemd0-mini / libsystemd0-mini-debuginfo / libudev-mini-devel / etc");
}
