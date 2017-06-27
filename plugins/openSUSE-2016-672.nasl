#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-672.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91483);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-0678");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2016-672)");
  script_summary(english:"Check for the openSUSE-2016-672 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Virtualbox was updated to 5.0.20 to fix the following issues :

Version bump to 5.0.20 (released 2016-04-28 by Oracle) This is a
maintenance release. The following items were fixed and/or added :

  - NAT Network: File VBoxNetNAT no longer requires suid

  - Storage: fixed a regression causing write requests from
    the BIOS to cause a Guru Meditation with the LsiLogic
    SCSI controller (5.0.18 regression; bug #15317)

  - Storage: several emulation fixes in the BusLogic SCSI
    controller emulation

  - NAT Network: support TCP in DNS proxy (same problem as
    in bug #14736 for NAT)

  - NAT: rework handling of port-forwarding rules (bug
    #13570)

  - NAT: rewrite host resolver to handle more query types
    and make it asynchronous so that a stalled lookup
    doesn't block all NAT traffic

  - Snapshots: don't crash when restoring a snapshot which
    has more network adapters than the current state (ie
    when the snapshot uses ICH9 and the current state uses
    PIIX3)

  - Guest Control: various bugfixes for the copyfrom and
    copyto commands / API (bug #14336)

  - VBoxManage: list processor features on list hostinfo
    (bug #15334)

  - Linux hosts: fix for Linux 4.5 if CONFIG_NET_CLS_ACT is
    enabled (bug #15327)

  - Windows Additions: fixed performance issues with
    PowerPoint 2010 and the WDDM graphics drivers if Aero is
    disabled 

Bugfixes :

  - Apply proper fix for boo#964765 that causes guest VMs
    using NAT Network attachments to fail to get network
    access. The basic problem is that file
    /usr/lib/virtualbox/VBoxNetNAT needs to have suid
    privilege, and the spec file was failing to set the
    appropriate permissions. 

  - Implement VirtualBox version 5.0.18 in openSUSE 13.2.
    Previous to this point, oS 13.2 had been using 4.3.X,
    which was the VB series when 13.2 was released. This
    policy has been changed so that a fix for CVE-2016-0678
    can be included in 13.2. Bug report b.o.o #97366
    discusses this vulnerability. This submission also fixes
    the bug in VB 5.0.18 that prevents proper operation for
    guest VMs configured to use LsiLogic adapter for disks.
    See ticket: https://www.virtualbox.org/ticket/15317 for
    a description of the problem, and changeset:
    https://www.virtualbox.org/changeset/60565/vbox for the
    fix, which is implemented in file
    'changeset_60565.diff'. 

Version bump to 5.0.18 (released 2016-04-18 by Oracle) This is a
maintenance release. The following items were fixed and/or added :

  - GUI: position off-screen windows to be fully visible
    again on relaunch in consistence with default-behavior
    (bug #15226)

  - GUI: fixed the View menu / Full-screen Mode behavior on
    Mac OS X El Capitan

  - GUI: fixed a test which allowed to encrypt a hard disk
    with an empty password

  - GUI: fixed a crash under certain conditions during VM
    shutdown

  - GUI: fixed the size of the VM list scrollbar in the VM
    selector when entering a group

  - PC speaker passthrough: fixes (Linux hosts only; bug
    #627)

  - Drag and drop: several fixes

  - SATA: fixed hotplug flag handling when EFI is used

  - Storage: fixed handling of encrypted disk images with
    SCSI controllers (bug #14812)

  - Storage: fixed possible crash with Solaris 7 if the
    BusLogic SCSI controller is used

  - USB: properly purge non-ASCII characters from USB
    strings (bugs #8801, #15222)

  - NAT Network: fixed 100% CPU load in VBoxNetNAT on Mac OS
    X under certain circumstances (bug #15223)

  - ACPI: fixed ACPI tables to make the display color
    management settings available again for older Windows
    versions (4.3.22 regression)

  - Guest Control: fixed VBoxManage copyfrom command (bug
    #14336)

  - Snapshots: fixed several problems when removing older
    snapshots (bug #15206)

  - VBoxManage: fixed --verbose output of the guestcontrol
    command

  - Windows hosts: hardening fixes required for recent
    Windows 10 insider builds (bugs #15245, #15296)

  - Windows hosts: fixed support of jumbo frames in with
    bridged networking (5.0.16 regression; bug #15209)

  - Windows hosts: don't prevent receiving multicast traffic
    if host-only adapters are installed (bug #8698)

  - Linux hosts: added support for the new naming scheme of
    NVME disks when creating raw disks

  - Solaris hosts / guests: properly sign the kernel modules
    (bug #12608)

  - Linux hosts / guests: Linux 4.5 fixes (bug #15251)

  - Linux hosts / guests: Linux 4.6 fixes (bug #15298)

  - Linux Additions: added a kernel graphics driver to
    support graphics when X.Org does not have root rights
    (bug #14732)

  - Linux/Solaris Additions: fixed several issues causing
    Linux/Solatis guests using software rendering when 3D
    acceleration is available

  - Windows Additions: fixed a hang with PowerPoint 2010 and
    the WDDM drivers if Aero is disabled"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.virtualbox.org/changeset/60565/vbox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.virtualbox.org/ticket/15317"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/06");
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

if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-5.0.20_k3.16.7_35-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-5.0.20-46.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-5.0.20-46.1") ) flag++;

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
