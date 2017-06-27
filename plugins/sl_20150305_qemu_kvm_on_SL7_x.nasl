#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82260);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/26 13:38:48 $");

  script_cve_id("CVE-2014-3640", "CVE-2014-7815", "CVE-2014-7840", "CVE-2014-8106");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the Cirrus blit region checks were insufficient. A
privileged guest user could use this flaw to write outside of VRAM-
allocated buffer boundaries in the host's QEMU process address space
with attacker-provided data. (CVE-2014-8106)

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

Bug fixes :

  - The KVM utility executed demanding routing update system
    calls every time it performed an MSI vector mask/unmask
    operation. Consequently, guests running legacy systems
    such as Scientific Linux 5 could, under certain
    circumstances, experience significant slowdown. Now, the
    routing system calls during mask/unmask operations are
    skipped, and the performance of legacy guests is now
    more consistent.

  - Due to a bug in the Internet Small Computer System
    Interface (iSCSI) driver, a qemu-kvm process terminated
    unexpectedly with a segmentation fault when the 'write
    same' command was executed in guest mode under the iSCSI
    protocol. This update fixes the bug, and the 'write
    same' command now functions in guest mode under iSCSI as
    intended.

  - The QEMU command interface did not properly handle
    resizing of cache memory during guest migration, causing
    QEMU to terminate unexpectedly with a segmentation
    fault. This update fixes the related code, and QEMU no
    longer crashes in the described situation.

Enhancements :

  - The maximum number of supported virtual CPUs (vCPUs) in
    a KVM guest has been increased to 240. This increases
    the number of virtual processing units that the user can
    assign to the guest, and therefore improves its
    performance potential.

  - Support for the 5th Generation Intel Core processors has
    been added to the QEMU hypervisor, the KVM kernel code,
    and the libvirt API. This allows KVM guests to use the
    following instructions and features: ADCX, ADOX,
    RDSFEED, PREFETCHW, and supervisor mode access
    prevention (SMAP).

  - The 'dump-guest-memory' command now supports crash dump
    compression. This makes it possible for users who cannot
    use the 'virsh dump' command to require less hard disk
    space for guest crash dumps. In addition, saving a
    compressed guest crash dump frequently takes less time
    than saving a non-compressed one."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=2166
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bfbba91"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcacard-1.5.3-86.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-86.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-86.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-img-1.5.3-86.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-86.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-86.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-86.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-86.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
