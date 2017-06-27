#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0349 and 
# Oracle Linux Security Advisory ELSA-2015-0349 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81803);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/03 14:52:25 $");

  script_cve_id("CVE-2014-3640", "CVE-2014-7815", "CVE-2014-7840", "CVE-2014-8106");
  script_bugtraq_id(66932, 66976, 67357, 67391, 67392, 67394, 67483, 69247, 69654, 70237, 70998, 71477, 71658);
  script_osvdb_id(111847, 113748, 115343, 115344);
  script_xref(name:"RHSA", value:"2015:0349");

  script_name(english:"Oracle Linux 7 : qemu-kvm (ELSA-2015-0349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0349 :

Updated qemu-kvm packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm packages provide
the user-space component for running virtual machines using KVM.

It was found that the Cirrus blit region checks were insufficient. A
privileged guest user could use this flaw to write outside of
VRAM-allocated buffer boundaries in the host's QEMU process address
space with attacker-provided data. (CVE-2014-8106)

An uninitialized data structure use flaw was found in the way the
set_pixel_format() function sanitized the value of bits_per_pixel. An
attacker able to access a guest's VNC console could use this flaw to
crash the guest. (CVE-2014-7815)

It was found that certain values that were read when loading RAM
during migration were not validated. A user able to alter the savevm
data (either on the disk or over the wire during migration) could use
either of these flaws to corrupt QEMU process memory on the
(destination) host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-7840)

A NULL pointer dereference flaw was found in the way QEMU handled UDP
packets with a source port and address of 0 when QEMU's user
networking was in use. A local guest user could use this flaw to crash
the guest. (CVE-2014-3640)

Red Hat would like to thank James Spadaro of Cisco for reporting
CVE-2014-7815, and Xavier Mehrenberger and Stephane Duverger of Airbus
for reporting CVE-2014-3640. The CVE-2014-8106 issue was found by
Paolo Bonzini of Red Hat, and the CVE-2014-7840 issue was discovered
by Michael S. Tsirkin of Red Hat.

Bug fixes :

* The KVM utility executed demanding routing update system calls every
time it performed an MSI vector mask/unmask operation. Consequently,
guests running legacy systems such as Red Hat Enterprise Linux 5
could, under certain circumstances, experience significant slowdown.
Now, the routing system calls during mask/unmask operations are
skipped, and the performance of legacy guests is now more consistent.
(BZ#1098976)

* Due to a bug in the Internet Small Computer System Interface (iSCSI)
driver, a qemu-kvm process terminated unexpectedly with a segmentation
fault when the 'write same' command was executed in guest mode under
the iSCSI protocol. This update fixes the bug, and the 'write same'
command now functions in guest mode under iSCSI as intended.
(BZ#1083413)

* The QEMU command interface did not properly handle resizing of cache
memory during guest migration, causing QEMU to terminate unexpectedly
with a segmentation fault. This update fixes the related code, and
QEMU no longer crashes in the described situation. (BZ#1066338)

Enhancements :

* The maximum number of supported virtual CPUs (vCPUs) in a KVM guest
has been increased to 240. This increases the number of virtual
processing units that the user can assign to the guest, and therefore
improves its performance potential. (BZ#1134408)

* Support for the 5th Generation Intel Core processors has been added
to the QEMU hypervisor, the KVM kernel code, and the libvirt API. This
allows KVM guests to use the following instructions and features:
ADCX, ADOX, RDSFEED, PREFETCHW, and supervisor mode access prevention
(SMAP). (BZ#1116117)

* The 'dump-guest-memory' command now supports crash dump compression.
This makes it possible for users who cannot use the 'virsh dump'
command to require less hard disk space for guest crash dumps. In
addition, saving a compressed guest crash dump frequently takes less
time than saving a non-compressed one. (BZ#1157798)

* This update introduces support for flight recorder tracing, which
uses SystemTap to automatically capture qemu-kvm data while the guest
machine is running. For detailed instructions on how to configure and
use flight recorder tracing, see the Virtualization Deployment and
Administration Guide, linked to in the References section below.
(BZ#1088112)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004884.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcacard-1.5.3-86.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-86.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-86.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-img-1.5.3-86.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-86.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-86.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-86.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard / libcacard-devel / libcacard-tools / qemu-img / qemu-kvm / etc");
}
