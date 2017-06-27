#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2012-0042.
#

include("compat.inc");

if (description)
{
  script_id(79484);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2009-0029", "CVE-2009-4307", "CVE-2011-4127", "CVE-2011-4131", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1179", "CVE-2012-1601", "CVE-2012-2121", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2313", "CVE-2012-2373", "CVE-2012-2383", "CVE-2012-2384");
  script_bugtraq_id(50655, 51176, 52197, 52274, 52533, 53162, 53166, 53488, 53614, 53721, 53965, 53971, 54063);
  script_osvdb_id(77100);

  script_name(english:"OracleVM 3.1 : kernel-uek (OVMSA-2012-0042)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Fix bug number for commit 'cciss: Update HPSA_BOUNDARY'
    (Joe Jin) [Orabug: 14681166]

  - cciss: Update HPSA_BOUNDARY. (Joe Jin) [Orabug:
    14319765]

  - KVM: introduce kvm_for_each_memslot macro (Maxim Uvarov)
    [Bugdb: 13966]

  - dl2k: Clean up rio_ioctl (Jeff Mahoney) [Orabug:
    14126896] (CVE-2012-2313)

  - NFSv4: include bitmap in nfsv4 get acl data (Andy
    Adamson) (CVE-2011-4131)

  - KVM: Fix buffer overflow in kvm_set_irq (Avi Kivity)
    [Bugdb: 13966] (CVE-2012-2137)

  - net: sock: validate data_len before allocating skb in
    sock_alloc_send_pskb (Jason Wang) [Bugdb: 13966]
    (CVE-2012-2136)

  - mm: pmd_read_atomic: fix 32bit PAE pmd walk vs
    pmd_populate SMP race condition (Andrea Arcangeli)
    [Bugdb: 13966] (CVE-2012-2373)

  - KVM: lock slots_lock around device assignment (Alex
    Williamson) [Bugdb: 13966] (CVE-2012-2121)

  - KVM: unmap pages from the iommu when slots are removed
    (Maxim Uvarov) [Bugdb: 13966] (CVE-2012-2121)

  - fcaps: clear the same personality flags as suid when
    fcaps are used (Eric Paris) [Bugdb: 13966]
    (CVE-2012-2123)

  - tilegx: enable SYSCALL_WRAPPERS support (Chris Metcalf)
    (CVE-2009-0029)

  - drm/i915: fix integer overflow in i915_gem_do_execbuffer
    (Xi Wang) [Orabug: 14107456] (CVE-2012-2384)

  - drm/i915: fix integer overflow in i915_gem_execbuffer2
    (Xi Wang) [Orabug: 14107445] (CVE-2012-2383)

  - [dm] do not forward ioctls from logical volumes to the
    underlying device (Joe Jin) (CVE-2011-4127)

  - [block] fail SCSI passthrough ioctls on partition
    devices (Joe Jin) (CVE-2011-4127)

  - [block] add and use scsi_blk_cmd_ioctl (Joe Jin)
    [Orabug: 14056755] (CVE-2011-4127)

  - KVM: Ensure all vcpus are consistent with in-kernel
    irqchip settings (Avi Kivity) [Bugdb: 13871]
    (CVE-2012-1601)

  - regset: Return -EFAULT, not -EIO, on host-side memory
    fault (H. Peter Anvin) (CVE-2012-1097)

  - regset: Prevent null pointer reference on readonly
    regsets (H. Peter Anvin) (CVE-2012-1097)

  - cifs: fix dentry refcount leak when opening a FIFO on
    lookup (Jeff Layton) (CVE-2012-1090)

  - mm: thp: fix pmd_bad triggering in code paths holding
    mmap_sem read mode (Andrea Arcangeli) (CVE-2012-1179)

  - ext4: fix undefined behavior in ext4_fill_flex_info (Xi
    Wang) (CVE-2009-4307)

  - ocfs2: clear unaligned io flag when dio fails (Junxiao
    Bi) [Orabug: 14063941]

  - aio: make kiocb->private NUll in init_sync_kiocb
    (Junxiao Bi) [Orabug: 14063941]

  - igb: Fix for Alt MAC Address feature on 82580 and later
    devices (Carolyn Wyborny) [Orabug: 14258706]

  - igb: Alternate MAC Address Updates for Func2&3 (Akeem G.
    Abodunrin) [Orabug: 14258706]

  - igb: Alternate MAC Address EEPROM Updates (Akeem G.
    Abodunrin) [Orabug: 14258706]

  - cciss: only enable cciss_allow_hpsa when for ol5 (Joe
    Jin) [Orabug: 14106006]

  - Revert 'cciss: remove controllers supported by hpsa'
    (Joe Jin) [Orabug: 14106006]

  - [scsi] hpsa: add all support devices for ol5 (Joe Jin)
    [Orabug: 14106006]

  - Disable VLAN 0 tagging for none VLAN traffic (Adnan
    Misherfi) [Orabug: 14406424]

  - x86: Add Xen kexec control code size check to linker
    script (Daniel Kiper)

  - drivers/xen: Export vmcoreinfo through sysfs (Daniel
    Kiper)

  - x86/xen/enlighten: Add init and crash kexec/kdump hooks
    (Maxim Uvarov)

  - x86/xen: Add kexec/kdump makefile rules (Daniel Kiper)

  - x86/xen: Add x86_64 kexec/kdump implementation (Daniel
    Kiper)

  - x86/xen: Add placeholder for i386 kexec/kdump
    implementation (Daniel Kiper)

  - x86/xen: Register resources required by kexec-tools
    (Daniel Kiper)

  - x86/xen: Introduce architecture dependent data for
    kexec/kdump (Daniel Kiper)

  - xen: Introduce architecture independent data for
    kexec/kdump (Daniel Kiper)

  - x86/kexec: Add extra pointers to transition page table
    PGD, PUD, PMD and PTE (Daniel Kiper)

  - kexec: introduce kexec_ops struct (Daniel Kiper)

  - SPEC: replace DEFAULTKERNEL from kernel-ovs to
    kernel-uek"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2012-October/000104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b90bca1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.1", reference:"kernel-uek-2.6.39-200.1.9.el5uek")) flag++;
if (rpm_check(release:"OVS3.1", reference:"kernel-uek-firmware-2.6.39-200.1.9.el5uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
