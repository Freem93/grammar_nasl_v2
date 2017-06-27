#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-487.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90593);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2014-9770", "CVE-2015-8842");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2016-487)");
  script_summary(english:"Check for the openSUSE-2016-487 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes several issues.

These security issues were fixed :

  - CVE-2014-9770, CVE-2015-8842: Don't allow read access to
    journal files to users (boo#972612)

These non-security issues were fixed :

  - Import commit 523777609a04fe9e590420e89f94ef07e3719baa:
    e5e362a udev: exclude MD from block device ownership
    event locking 8839413 udev: really exclude device-mapper
    from block device ownership event locking 66782e6 udev:
    exclude device-mapper from block device ownership event
    locking (boo#972727) 1386f57 tmpfiles: explicitly set
    mode for /run/log faadb74 tmpfiles: don't allow read
    access to journal files to users not in systemd-journal
    9b1ef37 tmpfiles: don't apply sgid and executable bit to
    journal files, only the directories they are contained
    in 011c39f tmpfiles: add ability to mask access mode by
    pre-existing access mode on files/directories 07e2d60
    tmpfiles: get rid of 'm' lines d504e28 tmpfiles: various
    modernizations f97250d systemctl: no need to pass --all
    if inactive is explicitly requested in list-units
    (boo#967122) 2686573 fstab-generator: fix automount
    option and don't start associated mount unit at boot
    (boo#970423) 5c1637d login: support more than just
    power-gpio-key (fate#318444) (boo#970860) 2c95ecd
    logind: add standard gpio power button support
    (fate#318444) (boo#970860) af3eb93 Revert
    'log-target-null-instead-kmsg' 555dad4 shorten hostname
    before checking for trailing dot (boo#965897) 522194c
    Revert 'log: honour the kernel's quiet cmdline argument'
    (boo#963230) cc94e47 transaction: downgrade warnings
    about wanted unit which are not found (boo#960158)
    eb3cfb3 Revert 'vhangup-on-all-consoles' 0c28752 remove
    WorkingDirectory parameter from emergency, rescue and
    console-shell.service (boo#959886) 1d6d840 Fix wrong
    substitution variable name in
    systemd-udev-root-symlink.service.in (boo#964355)

  - Don't ship boot.udev and systemd-journald.init anymore.
    It was used during the systemd transition when both
    sysvinit and systemd could be used on the same system"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972727"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-journal-gateway-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GUdev-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/20");
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

if ( rpm_check(release:"SUSE13.2", reference:"libgudev-1_0-0-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgudev-1_0-0-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgudev-1_0-devel-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-devel-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-mini-devel-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-mini1-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev-mini1-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev1-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libudev1-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nss-myhostname-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nss-myhostname-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-bash-completion-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-debugsource-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-devel-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-journal-gateway-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-journal-gateway-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-logger-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-debugsource-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-devel-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-mini-sysvinit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"systemd-sysvinit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-GUdev-1_0-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-mini-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"udev-mini-debuginfo-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgudev-1_0-0-32bit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgudev-1_0-0-debuginfo-32bit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libudev1-32bit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"nss-myhostname-32bit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"systemd-32bit-210.1459453449.5237776-25.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"systemd-debuginfo-32bit-210.1459453449.5237776-25.37.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libudev-mini-devel / libudev-mini1 / libudev-mini1-debuginfo / etc");
}
