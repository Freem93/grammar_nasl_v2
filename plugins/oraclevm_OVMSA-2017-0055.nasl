#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0055.
#

include("compat.inc");

if (description)
{
  script_id(99082);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2016-2857", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-5403", "CVE-2017-2615", "CVE-2017-2620");
  script_osvdb_id(135305, 138373, 138374, 142178, 151241, 152349);
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"OracleVM 3.4 : qemu-kvm (OVMSA-2017-0055)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - kvm-cirrus-fix-patterncopy-checks.patch [bz#1420487
    bz#1420489]

  -
    kvm-Revert-cirrus-allow-zero-source-pitch-in-pattern-fil
    .patch 

  -
    kvm-cirrus-add-blit_is_unsafe-call-to-cirrus_bitblt_cput
    .patch 

  - Resolves: bz#1420487 (EMBARGOED CVE-2017-2620 qemu-kvm:
    Qemu: display: cirrus: potential arbitrary code
    execution via cirrus_bitblt_cputovideo [rhel-6.9])

  - Resolves: bz#1420489 (EMBARGOED CVE-2017-2620
    qemu-kvm-rhev: Qemu: display: cirrus: potential
    arbitrary code execution via cirrus_bitblt_cputovideo
    [rhel-6.9])

  -
    kvm-cirrus_vga-fix-division-by-0-for-color-expansion-rop
    .patch 

  -
    kvm-cirrus_vga-fix-off-by-one-in-blit_region_is_unsafe.p
    atch 

  -
    kvm-display-cirrus-check-vga-bits-per-pixel-bpp-value.pa
    tch 

  -
    kvm-display-cirrus-ignore-source-pitch-value-as-needed-i
    .patch 

  -
    kvm-cirrus-handle-negative-pitch-in-cirrus_invalidate_re
    .patch 

  -
    kvm-cirrus-allow-zero-source-pitch-in-pattern-fill-rops.
    patch 

  - kvm-cirrus-fix-blit-address-mask-handling.patch
    [bz#1418231 bz#1419417]

  - kvm-cirrus-fix-oob-access-issue-CVE-2017-2615.patch
    [bz#1418231 bz#1419417]

  - Resolves: bz#1418231 (CVE-2017-2615 qemu-kvm: Qemu:
    display: cirrus: oob access while doing bitblt copy
    backward mode [rhel-6.9])

  - Resolves: bz#1419417 (CVE-2017-2615 qemu-kvm-rhev: Qemu:
    display: cirrus: oob access while doing bitblt copy
    backward mode [rhel-6.9])

  - kvm-Revert-iotests-Use-_img_info.patch [bz#1405882]

  -
    kvm-Revert-block-commit-speed-is-an-optional-parameter.p
    atch [bz#1405882]

  - kvm-Revert-iotests-Disable-086.patch [bz#1405882]

  - kvm-Revert-iotests-Fix-049-s-reference-output.patch
    [bz#1405882]

  - kvm-Revert-iotests-Fix-026-s-reference-output.patch
    [bz#1405882]

  - kvm-Revert-qcow2-Support-exact-L1-table-growth.patch
    [bz#1405882]

  -
    kvm-Revert-qcow2-Free-allocated-L2-cluster-on-error.patc
    h [bz#1405882]

  - kvm-net-check-packet-payload-length.patch [bz#1398214]

  - Resolves: bz#1398214 (CVE-2016-2857 qemu-kvm: Qemu: net:
    out of bounds read in net_checksum_calculate [rhel-6.9])

  - Reverts: bz#1405882 (test cases 026 030 049 086 and 095
    of qemu-iotests fail for qcow2 with
    qemu-kvm-rhev-0.12.1.2-2.498.el6)

  - kvm-qcow2-Free-allocated-L2-cluster-on-error.patch
    [bz#1405882]

  - kvm-qcow2-Support-exact-L1-table-growth.patch
    [bz#1405882]

  - kvm-iotests-Fix-026-s-reference-output.patch
    [bz#1405882]

  - kvm-iotests-Fix-049-s-reference-output.patch
    [bz#1405882]

  - kvm-iotests-Disable-086.patch [bz#1405882]

  - kvm-block-commit-speed-is-an-optional-parameter.patch
    [bz#1405882]

  - kvm-iotests-Use-_img_info.patch [bz#1405882]

  - Resolves: bz#1405882 (test cases 026 030 049 086 and 095
    of qemu-iotests fail for qcow2 with
    qemu-kvm-rhev-0.12.1.2-2.498.el6)

  - kvm-rename-qemu_aio_context-to-match-upstream.patch
    [bz#876993]

  -
    kvm-block-stop-relying-on-io_flush-in-bdrv_drain_all.pat
    ch [bz#876993]

  - kvm-block-add-bdrv_drain.patch [bz#876993]

  -
    kvm-block-avoid-very-long-pauses-at-the-end-of-mirroring
    .patch [bz#876993]

  - Resolves: bz#876993 (qemu-kvm: vm's become
    non-responsive during migrate disk load from 2 domains
    to a 3ed)

  - kvm-virtio-introduce-virtqueue_unmap_sg.patch
    [bz#1392520]

  - kvm-virtio-introduce-virtqueue_discard.patch
    [bz#1392520]

  - kvm-virtio-decrement-vq-inuse-in-virtqueue_discard.patch
    [bz#1392520]

  -
    kvm-balloon-fix-segfault-and-harden-the-stats-queue.patc
    h [bz#1392520]

  -
    kvm-virtio-balloon-discard-virtqueue-element-on-reset.pa
    tch [bz#1392520]

  - kvm-virtio-zero-vq-inuse-in-virtio_reset.patch
    [bz#1392520]

  -
    kvm-PATCH-1-4-e1000-pre-initialize-RAH-RAL-registers.pat
    ch [bz#1300626]

  - kvm-net-update-nic-info-during-device-reset.patch
    [bz#1300626]

  -
    kvm-net-e1000-update-network-information-when-macaddr-is
    .patch 

  -
    kvm-net-rtl8139-update-network-information-when-macaddr-
    .patch 

  - Resolves: bz#1300626 (e1000/rtl8139: qemu mac address
    can not be changed via set the hardware address in
    guest)

  - Resolves: bz#1392520 ([RHEL6.9] KVM guest shuts itself
    down after 128th reboot)

  -
    kvm-vmstate-fix-breakage-by-7e72abc382b700a72549e8147bde
    .patch 

  - Resolves: bz#1294941 (QEMU crash on snapshot revert when
    using Cirrus)

  - kvm-virtio-blk-Release-s-rq-queue-at-system_reset.patch
    [bz#1361490]

  - kvm-virtio-scsi-Prevent-assertion-on-missed-events.patch
    [bz#1333697]

  - Resolves: bz#1333697 (qemu-kvm:
    /builddir/build/BUILD/qemu-kvm-0.12.1.2/hw/virtio-scsi.c
    :724: virtio_scsi_push_event: Assertion `event == 0'
    failed)

  - Resolves: bz#1361490 (system_reset should clear pending
    request for error (virtio-blk))

  -
    kvm-qemu-img-add-support-for-fully-allocated-images.patc
    h [bz#1297653]

  -
    kvm-qemu-img-fix-usage-instruction-for-qemu-img-convert.
    patch [bz#1297653]

  -
    kvm-target-i386-warns-users-when-CPU-threads-1-for-non-I
    .patch 

  - Resolves: bz#1292678 (Qemu should report error when
    cmdline set threads=2 in amd host)

  - Resolves: bz#1297653 ('qemu-img convert' can't create a
    fully allocated image passed a '-S 0' option)

  - Resolves: bz#1320066 (Qemu should not report error when
    cmdline set threads=2 in Intel host)

  -
    kvm-rtl8139-flush-queued-packets-when-RxBufPtr-is-writte
    .patch 

  -
    kvm-block-Detect-unaligned-length-in-bdrv_qiov_is_aligne
    .patch 

  - kvm-ide-fix-halted-IO-segfault-at-reset.patch
    [bz#1281713]

  - kvm-atapi-fix-halted-DMA-reset.patch [bz#1281713]

  - Resolves: bz#1281713 (system_reset should clear pending
    request for error (IDE))

  - Resolves: bz#1321862 (Backport 'block: Detect unaligned
    length in bdrv_qiov_is_aligned')

  - Resolves: bz#1356924 (rtl8139 driver hangs in widows
    guests)

  -
    kvm-virtio-error-out-if-guest-exceeds-virtqueue-size.pat
    ch [bz#1359725]

  - Resolves: bz#1359725 (CVE-2016-5403 qemu-kvm: Qemu:
    virtio: unbounded memory allocation on host via guest
    leading to DoS [rhel-6.9])

  - kvm-Add-vga.h-unmodified-from-Linux.patch [bz#1331408]

  - kvm-vga.h-remove-unused-stuff-and-reformat.patch
    [bz#1331408]

  - kvm-vga-use-constants-from-vga.h.patch [bz#1331408]

  -
    kvm-vga-Remove-some-should-be-done-in-BIOS-comments.patc
    h [bz#1331408]

  -
    kvm-vga-fix-banked-access-bounds-checking-CVE-2016-3710.
    patch [bz#1331408]

  - kvm-vga-add-vbe_enabled-helper.patch [bz#1331408]

  - kvm-vga-factor-out-vga-register-setup.patch [bz#1331408]

  - kvm-vga-update-vga-register-setup-on-vbe-changes.patch
    [bz#1331408]

  -
    kvm-vga-make-sure-vga-register-setup-for-vbe-stays-intac
    .patch 

  - kvm-vga-add-sr_vbe-register-set.patch [bz#1331408
    bz#1346981]

  - Resolves: bz#1331408 (CVE-2016-3710 qemu-kvm: qemu:
    incorrect banked access bounds checking in vga module
    [rhel-6.9])

  - Resolves: bz#1346981 (Regression from CVE-2016-3712:
    windows installer fails to start)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000664.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2257e9a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-img package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"qemu-img-0.12.1.2-2.503.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img");
}
