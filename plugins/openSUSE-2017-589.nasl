#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-589.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100232);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/18 14:17:41 $");

  script_cve_id("CVE-2016-10155", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-5667", "CVE-2017-5856", "CVE-2017-5898");
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2017-589)");
  script_summary(english:"Check for the openSUSE-2017-589 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes several issues.

These security issues were fixed :

  - CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the
    bitblit copy routine cirrus_bitblt_cputovideo failed to
    check the memory region, allowing for an out-of-bounds
    write that allows for privilege escalation (bsc#1024972)

  - CVE-2017-2615: An error in the bitblt copy operation
    could have allowed a malicious guest administrator to
    cause an out of bounds memory access, possibly leading
    to information disclosure or privilege escalation
    (bsc#1023004)

  - CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to a memory leakage
    issue allowing a privileged user to leak host memory
    resulting in DoS (bsc#1023053)

  - CVE-2016-9776: The ColdFire Fast Ethernet Controller
    emulator support was vulnerable to an infinite loop
    issue while receiving packets in 'mcf_fec_receive'. A
    privileged user/process inside guest could have used
    this issue to crash the Qemu process on the host leading
    to DoS (bsc#1013285)

  - CVE-2016-9911: The USB EHCI Emulation support was
    vulnerable to a memory leakage issue while processing
    packet data in 'ehci_init_transfer'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for the host (bsc#1014111)

  - CVE-2016-9907: The USB redirector usb-guest support was
    vulnerable to a memory leakage flaw when destroying the
    USB redirector in 'usbredir_handle_destroy'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for a host (bsc#1014109)

  - CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1014702)

  - CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1014702)

  - CVE-2016-10155: The virtual hardware watchdog
    'wdt_i6300esb' was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1021129)

  - CVE-2017-5526: The ES1370 audio device emulation support
    was vulnerable to a memory leakage issue allowing a
    privileged user inside the guest to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1020589)

  - CVE-2017-5525: The ac97 audio device emulation support
    was vulnerable to a memory leakage issue allowing a
    privileged user inside the guest to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1020491)

  - CVE-2017-5667: The SDHCI device emulation support was
    vulnerable to an OOB heap access issue allowing a
    privileged user inside the guest to crash the Qemu
    process resulting in DoS or potentially execute
    arbitrary code with privileges of the Qemu process on
    the host (bsc#1022541)

  - CVE-2017-5898: The CCID Card device emulator support was
    vulnerable to an integer overflow allowing a privileged
    user inside the guest to crash the Qemu process
    resulting in DoS (bnc#1023907)

These non-security issues were fixed :

  - Fix post script for qemu-guest-agent rpm to actually
    activate the guest agent at rpm install time

  - Fixed various inaccuracies in cirrus vga device
    emulation

  - Fixed cause of infrequent migration failures from bad
    virtio device state (bsc#1020928)

  - Fixed virtio interface failure (bsc#1015048)

  - Fixed graphical update errors introduced by previous
    security fix (bsc#1016779)

  - Fixed uint64 property parsing and add regression tests
    (bsc#937125)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937125"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE42.1", reference:"qemu-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-debugsource-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ipxe-1.0.0-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-kvm-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-lang-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debugsource-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-seabios-1.8.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-sgabios-8-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-vgabios-1.8.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-testsuite-2.3.1-25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
