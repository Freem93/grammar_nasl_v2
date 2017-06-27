#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74560);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-0871");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2012-139)");
  script_summary(english:"Check for the openSUSE-2012-139 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Add fix-console-switch.patch: prevent console lockup
    (rhb#771563).

  - Add fix-quota.patch: correctly enable quota
    (rhb#773431).

  - Add passcredentials.patch: ensure compatibility with
    kernel 3.2 (bnc#743299).

  - Update modules_on_boot.patch to not cause failed state
    for systemd-modules-load.service (bnc#741481).

  - Ensure systemd show service status when started behind
    bootsplash and don't try to start when bootsplash isn't
    installed (bnc#736225).

  - Add fix-proc-net-unix-parsing.patch: fix /tmp socket
    cleanup on 32bits (mmeeks) (bnc#739438).

  - Add improve-readahead.patch: don't monopolize IO when
    replaying (git).

  - Add sysv_to_syslog_and_console.patch: ensure sysv
    services output is logged to syslog in addition to
    console (improve bnc#731342, bnc#681127).

  - Add fix-daemon-reload-reaping.patch: fix activating
    service being killed if daemon-reload is started (git).

  - Add no-variable-tcpwrappers.patch: fix manpage for
    tcpwrapper support (bnc#741023).

  - Add remote-fs-after-network.patch and update insserv
    patch: ensure remote-fs-pre.target is enabled and
    started before network mount points (bnc#744293).

  - Add dm-lvm-after-local-fs-pre-target.patch: ensure md /
    lvm /dmraid is started before mounting partitions, if
    fsck was disabled for them (bnc#733283).

  - Update lsb-header patch to correctly disable heuristic
    if X-Systemd-RemainAfterExit is specified (whatever its
    value)

  - Add fix-message-after-chkconfig.patch: don't complain if
    only sysv services are called in systemctl.

  - Add is-enabled-non-existing-service.patch: fix error
    message when running is-enabled on non-existing service.

  - Add remove-timedated-ntp-dependency.patch: don't require
    ntp to use timedated (partially fixes bnc#734831).

  - Add move-x11-socket.patch: change X11 socket symlink
    name (bnc#747154).

  - Add fix-is-enabled.patch: ensure systemctl is-enabled
    work properly when systemd isn't running.

  - Add logind-console.patch: do not bail logind if
    /dev/tty0 doesn't exist (bnc#733022, bnc#735047).

  - Add sysctl-modules.patch: ensure sysctl is started after
    modules are loaded (bnc#725412).

  - Fix warning in insserv patch.

  - Update avoid-random-seed-cycle.patch with better
    upstream approach.

  - Update storage-after-cryptsetup.patch to restart lvm
    before local-fs.target, not after it (bnc#740106).

  - Increase pam-config dependency (bnc#713319)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=725412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/29");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"systemd-37-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"systemd-debuginfo-37-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"systemd-debugsource-37-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"systemd-devel-37-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"systemd-sysvinit-37-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"systemd-32bit-37-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"systemd-debuginfo-32bit-37-3.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd-32bit / systemd / systemd-debuginfo-32bit / etc");
}
