#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-696.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74774);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2011-3571", "CVE-2012-0105", "CVE-2012-0111");
  script_osvdb_id(78413, 78442, 78443);

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-SU-2012:1323-1)");
  script_summary(english:"Check for the openSUSE-2012-696 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"VirtualBox was updated to 4.1.22 stable release, bringing lots of
security and also bugfixes.

The 4.1.22 release is brought to all openSUSE distributions to align
their versions.

changes in virtualbox 4.1.22 (maintenance release)

  - VMM: fixed a potential host crash triggered by shutting
    down a VM when another VM was running 

  - VMM: fixed a potential host crash under a high guest
    memory pressure (seen with Windows 8 guests)

  - VMM: respect RAM preallocation while restoring saved
    state.

  - VMM: fixed handling of task gates if VT-x/AMD-V is
    disabled

  - Storage: fixed audio CD passthrough for certain media
    players

  - USB: don't crash if a USB device is plugged or unplugged
    when saving or loading the VM state (SMP guests only)

  - RTC: fixed a potential corruption of CMOS bank 1

  - Mac OS X hosts: installer fixes for Leopard (4.1.20
    regression)

  - Windows Additions: fixed memory leak in VBoxTray (bug
    #10808)

  - changes in virtualbox 4.1.20 (maintenance release)

  - VMM: fixed a crash under rare circumstances for VMs
    running without hardware virtualization

  - VMM: fixed a code analysis bug for certain displacement
    instructions for VMs running without hardware
    virtualization

  - VMM: fixed an interpretion bug for TPR read instructions
    under rare conditions (AMD-V only)

  - Snapshots: fixed a crash when restoring an old snapshot
    when powering off a VM (bugs #9604, #10491)

  - VBoxSVC: be more tolerant against environment variables
    with strange encodings (bug #8780)

  - VGA: fixed wrong access check which might cause a crash
    under certain conditions

  - NAT: final fix for crashes under rare conditions (bug
    #10513)

  - Virtio-net: fixed the problem with receiving of GSO
    packets in Windows XP guests causing packet loss in
    host-to-VM transfers

  - HPET: several fixes (bugs #10170, #10306)

  - Clipboard: disable the clipboard by default for new VMs

  - BIOS: the PCI BIOS was not properly detected with the
    chipset type set to ICH9 (bugs #9301, #10327)

  - Mac OS X hosts: adaptions to Mountain Lion

  - Linux Installer: fixes for Gentoo Linux (bug #10642)

  - Linux guests: fixed mouse integration on Fedora 17
    guests (bug #2306)

  - Linux Additions: compile fixes for RHEL/CentOS 6.3 (bug
    #10756)

  - Linux Additions: compile fixes for Linux 3.5-rc1 and
    Linux 3.6-rc1 (bug #10709)

  - Solaris host: fixed a guru meditation while allocating
    large pages (bug #10600)

  - Solaris host: fixed possible kernel panics while freeing
    memory

  - Solaris Installer: fixed missing icon for menu and
    desktop shortcuts"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-10/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780711"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/28");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"python-virtualbox-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"python-virtualbox-debuginfo-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-debuginfo-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-debugsource-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-devel-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-kmp-default-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-kmp-default-debuginfo-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-kmp-desktop-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-kmp-pae-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-kmp-pae-debuginfo-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-tools-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-tools-debuginfo-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-x11-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-guest-x11-debuginfo-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-host-kmp-default-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-host-kmp-default-debuginfo-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-host-kmp-desktop-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-host-kmp-desktop-debuginfo-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-host-kmp-pae-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-host-kmp-pae-debuginfo-4.0.12_k2.6.37.6_0.20-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-qt-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"virtualbox-qt-debuginfo-4.0.12-0.48.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-virtualbox-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-virtualbox-debuginfo-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-debuginfo-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-debugsource-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-devel-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-default-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-desktop-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-pae-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-tools-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-tools-debuginfo-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-x11-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-x11-debuginfo-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-default-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-default-debuginfo-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-desktop-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-pae-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.1.22_k3.1.10_1.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-qt-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-qt-debuginfo-4.1.22-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-virtualbox-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-virtualbox-debuginfo-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-debuginfo-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-debugsource-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-devel-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-default-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-default-debuginfo-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-desktop-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-pae-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-pae-debuginfo-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-tools-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-tools-debuginfo-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-x11-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-x11-debuginfo-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-default-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-default-debuginfo-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-desktop-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-desktop-debuginfo-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-pae-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-pae-debuginfo-4.1.22_k3.4.6_2.10-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-qt-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-qt-debuginfo-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-websrv-4.1.22-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-websrv-debuginfo-4.1.22-1.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "virtualbox");
}
