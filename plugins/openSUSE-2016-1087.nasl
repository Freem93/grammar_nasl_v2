#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1087.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93596);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-3597", "CVE-2016-3612");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2016-1087)");
  script_summary(english:"Check for the openSUSE-2016-1087 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Virtualbox was updated to 5.0.26 to fix the following issues :

This update fixes various security issues.

  - CVE-2016-3612: An unspecified vulnerability in the
    Oracle VM VirtualBox component in Oracle Virtualization
    VirtualBox before 5.0.22 allowed remote attackers to
    affect confidentiality via vectors related to Core.
    (boo#990369).

  - CVE-2016-3597: Unspecified vulnerability in the Oracle
    VM VirtualBox component in Oracle Virtualization
    VirtualBox before 5.0.26 allows local users to affect
    availability via vectors related to Core. (bsc#990370)

  - Update the host <-> guest KMP conflict dependencies to
    no longer refer to the old name (boo#983927).

This is a maintenance release. The following items were fixed and/or
added :

  - VMM: fixed a bug in the task switching code (ticket
    #15571)

  - GUI: allow to overwrite an existing file when saving a
    log file (bug #8034)

  - GUI: fixed screenshot if the VM is started in separate
    mode

  - Audio: improved recording from USB headsets and other
    sources which might need conversion of captured data

  - Audio: fixed regression of not having any audio
    available on Solaris hosts

  - VGA: fixed an occasional hang when running Windows
    guests with 3D enabled

  - Storage: fixed a possible endless reconnect loop for the
    iSCSI backend if connecting to the target succeeds but
    further I/O requests cause a disconnect

  - Storage: fixed a bug when resizing certain VDI images
    which resulted in using the whole disk on the host (bug
    #15582)

  - EFI: fixed access to devices attached to SATA port 2 and
    higher (bug #15607)

  - API: fixed video recording with VBoxHeadless (bug
    #15443)

  - API: don't crash if there is no graphics controller
    configured (bug #15628)

  - VBoxSVC: fixed several memory leaks when handling .dmg
    images

Version bump to 5.0.24 (released 2016-06-28 by Oracle) This is a
maintenance release. The following items were fixed and/or added :

  - VMM: reverted to the old I/O-APIC code for now to fix
    certain regressions with 5.0.22 (bug #15529). This means
    that the networking performance with certain guests will
    drop to the 5.0.20 level (bug #15295). One workaround is
    to disable GRO for Linux guests.

  - Main: when taking a screenshot, don't save garbage for
    blanked screens

  - NAT: correctly parse resolv.conf file with multiple
    separators (5.0.22 regression)

  - Storage: fixed a possible corruption of stream optimized
    VMDK images from VMware when opened in read/write mode
    for the first time

  - Audio: imlemented dynamic re-attaching of input/output
    devices on Mac OS X hosts

  - ACPI: notify the guest when the battery / AC state
    changes instead of relying on guest polling

  - Linux hosts: fixed VERR_VMM_SET_JMP_ABORTED_RESUME Guru
    Meditations on hosts with Linux 4.6 or later (bug
    #15439)

Version bump to 5.0.22 (released 2016-06-16 by Oracle) This is a
maintenance release. The following items were fixed and/or added :

  - VMM: fixes for certain Intel Atom hosts (bug #14915)

  - VMM: properly restore the complete FPU state for 32-bit
    guests on 64-bit hosts on Intel Sandy Bridge and Ivy
    Bridge CPUs

  - VMM: new I/O-APIC implementation fixing several bugs and
    improving the performance under certain conditions (bug
    #15295 and others)

  - VMM: fixed a potential Linux guest panic on AMD hosts

  - VMM: fixed a potential hang with 32-bit EFI guests on
    Intel CPUs (VT-x without unrestricted guest execution)

  - GUI: don't allow to start subsequent separate VM
    instances

  - GUI: raised upper limit for video capture screen
    resolution (bug #15432)

  - GUI: warn if the VM has less than 128MB VRAM configured
    and 3D enabled

  - Main: when monitoring DNS configuration changes on
    Windows hosts avoid false positives from competing DHCP
    renewals. This should fix NAT link flaps when host has
    multiple DHCP configured interfaces, in particular when
    the host uses OpnVPN.

  - Main: properly display an error message if the VRDE
    server cannot be enabled at runtime, for example because
    another service is using the same port

  - NAT: Initialize guest address guess for wildcard
    port-forwarding rules with default guest address (bug
    #15412)

  - VGA: fix for a problem which made certain legacy guests
    crash under certain conditions (bug #14811)

  - OVF: fixed import problems for some appliances using an
    AHCI controller created by 3rd party applications

  - SDK: reduced memory usage in the webservice Java
    bindings

  - Windows Additions: fixes to retain the guest display
    layout when resizing or disabling the guest monitors

  - Linux hosts: EL 6.8 fix (bug #15411)

  - Linux hosts: Linux 4.7 fix (bug #15459)

  - Linux Additions: Linux 4.7 fixes (bug #15444)

  - Linux Additions: fix for certain 32-bit guests (5.0.18
    regression; bug #15320)

  - Linux Additions: fixed mouse pointer offset (5.0.18
    regression; bug #15324)

  - Linux Additions: made old X.Org releases work again with
    kernels 3.11 and later (5.0.18 regression; bug #15319)

  - Linux Additions: fixed X.Org crash after hard guest
    reset (5.0.18 regression; bug #15354)

  - Linux Additions: don't stop the X11 setup if loading the
    shared folders module fails (5.0.18 regression)

  - Linux Additions: don't complain if the Drag and Drop
    service is not available on the host

  - Solaris Additions: added support for X.org 1.18"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/20");
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

if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-5.0.26_k3.16.7_42-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-5.0.26-51.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-5.0.26-51.1") ) flag++;

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
