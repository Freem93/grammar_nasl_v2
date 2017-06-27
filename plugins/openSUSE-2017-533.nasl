#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-533.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99956);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/05 13:31:48 $");

  script_cve_id("CVE-2017-3513", "CVE-2017-3538", "CVE-2017-3558", "CVE-2017-3559", "CVE-2017-3561", "CVE-2017-3563", "CVE-2017-3575", "CVE-2017-3576", "CVE-2017-3587");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2017-533)");
  script_summary(english:"Check for the openSUSE-2017-533 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox to version 5.1.22 fixes the following
issues :

These security issues were fixed (bsc#1034854) :

  - CVE-2017-3561: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Core).
    Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle
    VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2017-3563: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Core).
    Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle
    VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2017-3576: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Core).
    Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle
    VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks of this vulnerability can
    result in takeover of Oracle VM VirtualBox.

  - CVE-2017-3587: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Shared
    Folder). Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure
    where Oracle VM VirtualBox executes to compromise Oracle
    VM VirtualBox. Successful attacks of this vulnerability
    can result in unauthorized creation, deletion or
    modification access to critical data or all Oracle VM
    VirtualBox accessible data and unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Oracle VM VirtualBox.

  - CVE-2017-3575: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Core).
    Easily exploitable vulnerability allows high privileged
    attacker with logon to the infrastructure where Oracle
    VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or
    modification access to critical data or all Oracle VM
    VirtualBox accessible data and unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Oracle VM VirtualBox.

  - CVE-2017-3538: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Shared
    Folder). Difficult to exploit vulnerability allows low
    privileged attacker with logon to the infrastructure
    where Oracle VM VirtualBox executes to compromise Oracle
    VM VirtualBox. Successful attacks of this vulnerability
    can result in unauthorized creation, deletion or
    modification access to critical data or all Oracle VM
    VirtualBox accessible data as well as unauthorized
    access to critical data or complete access to all Oracle
    VM VirtualBox accessible data.

  - CVE-2017-3513: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Core).
    Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure
    where Oracle VM VirtualBox executes to compromise Oracle
    VM VirtualBox. Successful attacks of this vulnerability
    can result in unauthorized read access to a subset of
    Oracle VM VirtualBox accessible data.

  - CVE-2017-3558: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Core).
    Easily exploitable vulnerability allows unauthenticated
    attacker with logon to the infrastructure where Oracle
    VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle VM
    VirtualBox as well as unauthorized update, insert or
    delete access to some of Oracle VM VirtualBox accessible
    data and unauthorized read access to a subset of Oracle
    VM VirtualBox accessible data.

  - CVE-2017-3559: Vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization (subcomponent: Core).
    Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle
    VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle VM
    VirtualBox as well as unauthorized update, insert or
    delete access to some of Oracle VM VirtualBox accessible
    data and unauthorized read access to a subset of Oracle
    VM VirtualBox accessible data. These non-security issues
    were fixed :

  - GUI: don't check if the Extension Pack is up-to-date if
    the user is about to install a new Extension Pack 

  - GUI: fixed a possible crash when switching a
    multi-monitor VM into full-screen or seamless mode

  - GUI: several mini-toolbar fixes in full-screen /
    seamless mode 

  - GUI: don't crash on restoring defaults in the appliance
    import dialog

  - ICH9: fix for Windows guests with a huge amount (more
    than 64G) of guest memory

  - BIOS: fixed El Torito hard disk emulation geometry
    calculation 

  - VMM: fixed VERR_IEM_INSTR_NOT_IMPLEMENTED Guru
    Meditation under certain conditions

  - Storage: fixed a potential hang under rare circumstances

  - Storage: fixed a potential crash under rare
    circumstances (asynchronous I/O disabled or during
    maintenance file operations like merging snapshots)

  - Linux hosts: make the ALSA backend work again as well as
    loading the GL libraries on certain hosts

  - Linux Additions: fixed mount.vboxsf symlink problem"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034854"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-debuginfo-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debuginfo-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debugsource-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-devel-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-desktop-icons-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-5.1.22_k4.4.57_18.3-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.22_k4.4.57_18.3-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-debuginfo-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-debuginfo-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-5.1.22_k4.4.57_18.3-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-debuginfo-5.1.22_k4.4.57_18.3-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-source-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-debuginfo-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-5.1.22-19.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-debuginfo-5.1.22-19.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtualbox / python-virtualbox-debuginfo / virtualbox / etc");
}
