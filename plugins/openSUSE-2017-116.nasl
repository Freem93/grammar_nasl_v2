#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-116.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96623);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9381", "CVE-2016-9776", "CVE-2016-9845", "CVE-2016-9846", "CVE-2016-9907", "CVE-2016-9908", "CVE-2016-9911", "CVE-2016-9912", "CVE-2016-9913", "CVE-2016-9921", "CVE-2016-9922");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2017-116)");
  script_summary(english:"Check for the openSUSE-2017-116 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qemu was updated to fix several issues.

These security issues were fixed :

  - CVE-2016-9102: Memory leak in the v9fs_xattrcreate
    function in hw/9pfs/9p.c in allowed local guest OS
    administrators to cause a denial of service (memory
    consumption and QEMU process crash) via a large number
    of Txattrcreate messages with the same fid number
    (bsc#1014256).

  - CVE-2016-9103: The v9fs_xattrcreate function in
    hw/9pfs/9p.c in allowed local guest OS administrators to
    obtain sensitive host heap memory information by reading
    xattribute values writing to them (bsc#1007454).

  - CVE-2016-9381: Improper processing of shared rings
    allowing guest administrators take over the qemu
    process, elevating their privilege to that of the qemu
    process (bsc#1009109)

  - CVE-2016-9776: The ColdFire Fast Ethernet Controller
    emulator support was vulnerable to an infinite loop
    issue while receiving packets in 'mcf_fec_receive'. A
    privileged user/process inside guest could have used
    this issue to crash the Qemu process on the host leading
    to DoS (bsc#1013285).

  - CVE-2016-9845: The Virtio GPU Device emulator support as
    vulnerable to an information leakage issue while
    processing the 'VIRTIO_GPU_CMD_GET_CAPSET_INFO' command.
    A guest user/process could have used this flaw to leak
    contents of the host memory (bsc#1013767).

  - CVE-2016-9846: The Virtio GPU Device emulator support
    was vulnerable to a memory leakage issue while updating
    the cursor data in update_cursor_data_virgl. A guest
    user/process could have used this flaw to leak host
    memory bytes, resulting in DoS for the host
    (bsc#1013764).

  - CVE-2016-9907: The USB redirector usb-guest support was
    vulnerable to a memory leakage flaw when destroying the
    USB redirector in 'usbredir_handle_destroy'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for a host (bsc#1014109).

  - CVE-2016-9908: The Virtio GPU Device emulator support
    was vulnerable to an information leakage issue while
    processing the 'VIRTIO_GPU_CMD_GET_CAPSET' command. A
    guest user/process could have used this flaw to leak
    contents of the host memory (bsc#1014514).

  - CVE-2016-9911: The USB EHCI Emulation support was
    vulnerable to a memory leakage issue while processing
    packet data in 'ehci_init_transfer'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for the host (bsc#1014111).

  - CVE-2016-9912: The Virtio GPU Device emulator support
    was vulnerable to a memory leakage issue while
    destroying gpu resource object in
    'virtio_gpu_resource_destroy'. A guest user/process
    could have used this flaw to leak host memory bytes,
    resulting in DoS for the host (bsc#1014112).

  - CVE-2016-9913: VirtFS was vulnerable to memory leakage
    issue via its '9p-handle' or '9p-proxy' backend drivers.
    A privileged user inside guest could have used this flaw
    to leak host memory, thus affecting other services on
    the host and/or potentially crash the Qemu process on
    the host (bsc#1014110).

These non-security issues were fixed :

  - Fixed uint64 property parsing and add regression tests
    (bsc#937125)

  - Added a man page for kvm_stat

  - Fix crash in vte (bsc#1008519)

  - Various upstream commits targeted towards stable
    releases (bsc#1013341)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937125"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");
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

if ( rpm_check(release:"SUSE42.2", reference:"qemu-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-arm-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-arm-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-curl-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-curl-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-dmg-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-dmg-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-iscsi-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-iscsi-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-ssh-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-ssh-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-debugsource-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-extra-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-extra-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-guest-agent-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-guest-agent-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ipxe-1.0.0-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-kvm-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-lang-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-debugsource-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ppc-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ppc-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-s390-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-s390-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-seabios-1.9.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-sgabios-8-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-testsuite-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-tools-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-tools-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-vgabios-1.9.1-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-x86-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-x86-debuginfo-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"qemu-block-rbd-2.6.2-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.6.2-26.1") ) flag++;

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
