#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0051.
#

include("compat.inc");

if (description)
{
  script_id(91316);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-5165", "CVE-2015-5279", "CVE-2015-7512", "CVE-2016-1714", "CVE-2016-3710");
  script_osvdb_id(125706, 127494, 130889, 132798, 138374);

  script_name(english:"OracleVM 3.4 : qemu-kvm (OVMSA-2016-0051)");
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

  - kvm-Add-vga.h-unmodified-from-Linux.patch [bz#1331407]

  - kvm-vga.h-remove-unused-stuff-and-reformat.patch
    [bz#1331407]

  - kvm-vga-use-constants-from-vga.h.patch [bz#1331407]

  -
    kvm-vga-Remove-some-should-be-done-in-BIOS-comments.patc
    h [bz#1331407]

  -
    kvm-vga-fix-banked-access-bounds-checking-CVE-2016-3710.
    patch [bz#1331407]

  - kvm-vga-add-vbe_enabled-helper.patch [bz#1331407]

  - kvm-vga-factor-out-vga-register-setup.patch [bz#1331407]

  - kvm-vga-update-vga-register-setup-on-vbe-changes.patch
    [bz#1331407]

  -
    kvm-vga-make-sure-vga-register-setup-for-vbe-stays-intac
    .patch 

  - Resolves: bz#1331407 (EMBARGOED CVE-2016-3710 qemu-kvm:
    qemu: incorrect banked access bounds checking in vga
    module [rhel-6.8.z])

  - Revert 'warning when CPU threads>1 for non-Intel CPUs'
    fix

  -
    kvm-qemu-ga-implement-win32-guest-set-user-password.patc
    h [bz#1174181]

  - kvm-util-add-base64-decoding-function.patch [bz#1174181]

  - kvm-qga-convert-to-use-error-checked-base64-decode.patch
    [bz#1174181]

  -
    kvm-qga-use-more-idiomatic-qemu-style-eol-operators.patc
    h [bz#1174181]

  - kvm-qga-use-size_t-for-wcslen-return-value.patch
    [bz#1174181]

  -
    kvm-qga-use-wide-chars-constants-for-wchar_t-comparisons
    .patch 

  - kvm-qga-fix-off-by-one-length-check.patch [bz#1174181]

  - kvm-qga-check-utf8-to-utf16-conversion.patch
    [bz#1174181]

  - Resolves: bz#1174181 (RFE: provide QEMU guest agent
    command for setting root account password (Linux guest))

  - kvm-hw-qxl-qxl_send_events-nop-if-stopped.patch
    [bz#1290743]

  -
    kvm-block-mirror-fix-full-sync-mode-when-target-does-not
    .patch [bz#971312]

  - Resolves: bz#1290743 (qemu-kvm core dumped when repeat
    system_reset 20 times during guest boot)

  - Resolves: bz#971312 (block: Mirroring to raw block
    device doesn't zero out unused blocks)

  - Mon Feb 08 2016 Miroslav Rezanina < - 0.12.1.2-2.488.el6

  - Fixed qemu-ga path configuration [bz#1213233]

  - Resolves: bz#1213233 ([virtagent] The default path
    '/etc/qemu/fsfreeze-hook' for 'fsfreeze-hook' script
    doesn't exist)

  -
    kvm-virtio-scsi-use-virtqueue_map_sg-when-loading-reques
    .patch 

  - kvm-scsi-disk-fix-cmd.mode-field-typo.patch [bz#1249740]

  - Resolves: bz#1249740 (Segfault occurred at Dst VM while
    completed migration upon ENOSPC)

  -
    kvm-blockdev-Error-out-on-negative-throttling-option-val
    .patch 

  -
    kvm-fw_cfg-add-check-to-validate-current-entry-value-CVE
    .patch 

  - Resolves: bz#1294619 (Guest should failed to boot if set
    iops,bps to negative number)

  - Resolves: bz#1298046 (CVE-2016-1714 qemu-kvm: Qemu:
    nvram: OOB r/w access in processing firmware
    configurations [rhel-6.8])

  - kvm-Change-fsfreeze-hook-default-location.patch
    [bz#1213233]

  - kvm-qxl-replace-pipe-signaling-with-bottom-half.patch
    [bz#1290743]

  - Resolves: bz#1213233 ([virtagent] The default path
    '/etc/qemu/fsfreeze-hook' for 'fsfreeze-hook' script
    doesn't exist)

  - Resolves: bz#1290743 (qemu-kvm core dumped when repeat
    system_reset 20 times during guest boot)

  - kvm-qga-flush-explicitly-when-needed.patch [bz#1210246]

  - kvm-qga-add-guest-set-user-password-command.patch
    [bz#1174181]

  -
    kvm-qcow2-Zero-initialise-first-cluster-for-new-images.p
    atch [bz#1223216]

  -
    kvm-Documentation-Warn-against-qemu-img-on-active-image.
    patch [bz#1297424]

  -
    kvm-target-i386-warns-users-when-CPU-threads-1-for-non-I
    .patch 

  - kvm-qemu-options-Fix-texinfo-markup.patch [bz#1250442]

  - kvm-qga-Fix-memory-allocation-pasto.patch []

  -
    kvm-block-raw-posix-Open-file-descriptor-O_RDWR-to-work-
    .patch 

  - Resolves: bz#1174181 (RFE: provide QEMU guest agent
    command for setting root/administrator account password)

  - Resolves: bz#1210246 ([virtagent]The 'write' content is
    lost if 'read' it before flush through guest agent)

  - Resolves: bz#1223216 (qemu-img can not create qcow2
    image when backend is block device)

  - Resolves: bz#1250442 (qemu-doc.html bad markup in
    section 3.3 Invocation)

  - Resolves: bz#1268347 (posix_fallocate emulation on NFS
    fails with Bad file descriptor if fd is opened O_WRONLY)

  - Resolves: bz#1292678 (Qemu should report error when
    cmdline set threads=2 in amd host)

  - Resolves: bz#1297424 (Add warning about running qemu-img
    on active VMs to its manpage)

  - kvm-rtl8139-Fix-receive-buffer-overflow-check.patch
    [bz#1262866]

  -
    kvm-rtl8139-Do-not-consume-the-packet-during-overflow-in
    .patch 

  - Resolves: bz#1262866 ([RHEL6] Package is 100% lost when
    ping from host to Win2012r2 guest with 64000 size)

  -
    kvm-qemu-kvm-get-put-MSR_TSC_AUX-across-reset-and-migrat
    .patch 

  -
    kvm-qcow2-Discard-VM-state-in-active-L1-after-creating-s
    .patch 

  -
    kvm-net-pcnet-add-check-to-validate-receive-data-size-CV
    .patch 

  - kvm-pcnet-fix-rx-buffer-overflow-CVE-2015-7512.patch
    [bz#1286567]

  - Resolves: bz#1219908 (Writing snapshots with 'virsh
    snapshot-create-as' command slows as more snapshots are
    created)

  - Resolves: bz#1265428 (contents of MSR_TSC_AUX are not
    migrated)

  - Resolves: bz#1286567 (CVE-2015-7512 qemu-kvm: Qemu: net:
    pcnet: buffer overflow in non-loopback mode [rhel-6.8])

  -
    kvm-net-add-checks-to-validate-ring-buffer-pointers-CVE-
    .patch 

  - Resolves: bz#1263275 (CVE-2015-5279 qemu-kvm: qemu: Heap
    overflow vulnerability in ne2000_receive function
    [rhel-6.8])

  -
    kvm-virtio-rng-fix-segfault-when-adding-a-virtio-pci-rng
    .patch 

  - kvm-qga-commands-posix-Fix-bug-in-guest-fstrim.patch
    [bz#1213236]

  -
    kvm-rtl8139-avoid-nested-ifs-in-IP-header-parsing-CVE-20
    .patch 

  -
    kvm-rtl8139-drop-tautologous-if-ip-.-statement-CVE-2015-
    .patch 

  -
    kvm-rtl8139-skip-offload-on-short-Ethernet-IP-header-CVE
    .patch 

  -
    kvm-rtl8139-check-IP-Header-Length-field-CVE-2015-5165.p
    atch [bz#1248763]

  -
    kvm-rtl8139-check-IP-Total-Length-field-CVE-2015-5165.pa
    tch [bz#1248763]

  -
    kvm-rtl8139-skip-offload-on-short-TCP-header-CVE-2015-51
    .patch 

  -
    kvm-rtl8139-check-TCP-Data-Offset-field-CVE-2015-5165.pa
    tch [bz#1248763]

  - Resolves: bz#1213236 ([virtagent] 'guest-fstrim' failed
    for guest with os on spapr-vscsi disk)

  - Resolves: bz#1230068 (Segmentation fault when re-adding
    virtio-rng-pci device)

  - Resolves: bz#1248763 (CVE-2015-5165 qemu-kvm: Qemu:
    rtl8139 uninitialized heap memory information leakage to
    guest [rhel-6.8])"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000467.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-img package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS3.4", reference:"qemu-img-0.12.1.2-2.491.el6_8.1")) flag++;

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
