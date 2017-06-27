#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0043.
#

include("compat.inc");

if (description)
{
  script_id(97409);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/28 15:14:29 $");

  script_cve_id("CVE-2016-2857", "CVE-2017-2615");
  script_osvdb_id(135305, 151241);
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"OracleVM 3.4 : qemu-kvm (OVMSA-2017-0043)");
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
    [bz#1418230 bz#1419416]

  - kvm-cirrus-fix-oob-access-issue-CVE-2017-2615.patch
    [bz#1418230 bz#1419416]

  - Resolves: bz#1418230 (CVE-2017-2615 qemu-kvm: Qemu:
    display: cirrus: oob access while doing bitblt copy
    backward mode [rhel-6.8.z])

  - Resolves: bz#1419416 (CVE-2017-2615 qemu-kvm-rhev: Qemu:
    display: cirrus: oob access while doing bitblt copy
    backward mode [rhel-6.8.z])

  - kvm-net-check-packet-payload-length.patch [bz#1398213]

  - Resolves: bz#1398213 (CVE-2016-2857 qemu-kvm: Qemu: net:
    out of bounds read in net_checksum_calculate
    [rhel-6.8.z])

  - kvm-virtio-introduce-virtqueue_unmap_sg.patch
    [bz#1408389]

  - kvm-virtio-introduce-virtqueue_discard.patch
    [bz#1408389]

  - kvm-virtio-decrement-vq-inuse-in-virtqueue_discard.patch
    [bz#1408389]

  -
    kvm-balloon-fix-segfault-and-harden-the-stats-queue.patc
    h [bz#1408389]

  -
    kvm-virtio-balloon-discard-virtqueue-element-on-reset.pa
    tch [bz#1408389]

  - kvm-virtio-zero-vq-inuse-in-virtio_reset.patch
    [bz#1408389]

  - Resolves: bz#1408389 ([RHEL6.8.z] KVM guest shuts itself
    down after 128th reboot)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-February/000652.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efb29ba9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-img package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/27");
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
if (rpm_check(release:"OVS3.4", reference:"qemu-img-0.12.1.2-2.491.el6_8.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img");
}
