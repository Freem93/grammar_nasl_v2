#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-305.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97564);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/07 17:25:25 $");

  script_cve_id("CVE-2017-2616");

  script_name(english:"openSUSE Security Update : util-linux (openSUSE-2017-305)");
  script_summary(english:"Check for the openSUSE-2017-305 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for util-linux fixes the following issues :

This security issue was fixed :

  - CVE-2017-2616: In su with PAM support it was possible
    for local users to send SIGKILL to selected other
    processes with root privileges (bsc#1023041).

This non-security issues were fixed :

  - lscpu: Implement WSL detection and work around crash
    (bsc#1019332)

  - fstrim: De-duplicate btrfs sub-volumes for 'fstrim -a'
    and bind mounts (bsc#1020077)

  - Fix regressions in safe loop re-use patch set for
    libmount (bsc#1012504)

  - Disable ro checks for mtab (bsc#1012632)

  - Ensure that the option 'users,exec,dev,suid' work as
    expected on NFS mounts (bsc#1008965)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023041"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libblkid-devel-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libblkid1-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libblkid1-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmount-devel-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmount1-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmount1-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmartcols-devel-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmartcols1-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmartcols1-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libuuid-devel-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libuuid1-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libuuid1-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-libmount-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-libmount-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-libmount-debugsource-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"util-linux-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"util-linux-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"util-linux-debugsource-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"util-linux-lang-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"util-linux-systemd-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"util-linux-systemd-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"util-linux-systemd-debugsource-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"uuidd-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"uuidd-debuginfo-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libblkid-devel-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libblkid1-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmount-devel-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmount1-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libuuid-devel-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libuuid1-32bit-2.25-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.25-21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-libmount / python-libmount-debuginfo / etc");
}
