#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60497);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-5093", "CVE-2007-6716", "CVE-2008-1514", "CVE-2008-3272", "CVE-2008-3528", "CVE-2008-4210");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"  - a flaw was found in the Linux kernel's Direct-IO
    implementation. This could have allowed a local
    unprivileged user to cause a denial of service.
    (CVE-2007-6716, Important)

  - when running ptrace in 31-bit mode on an IBM S/390 or
    IBM System z kernel, a local unprivileged user could
    cause a denial of service by reading from or writing
    into a padding area in the user_regs_struct32 structure.
    (CVE-2008-1514, Important)

  - the do_truncate() and generic_file_splice_write()
    functions did not clear the setuid and setgid bits. This
    could have allowed a local unprivileged user to obtain
    access to privileged information. (CVE-2008-4210,
    Important)

  - Tobias Klein reported a missing check in the Linux
    kernel's Open Sound System (OSS) implementation. This
    deficiency could have led to an information leak.
    (CVE-2008-3272, Moderate)

  - a potential denial of service attack was discovered in
    the Linux kernel's PWC USB video driver. A local
    unprivileged user could have used this flaw to bring the
    kernel USB subsystem into the busy-waiting state.
    (CVE-2007-5093, Low)

  - the ext2 and ext3 file systems code failed to properly
    handle corrupted data structures, leading to a possible
    local denial of service issue when read or write
    operations were performed. (CVE-2008-3528, Low)

In addition, these updated packages fix the following bugs :

  - when using the CIFS 'forcedirectio' option, appending to
    an open file on a CIFS share resulted in that file being
    overwritten with the data to be appended.

  - a kernel panic occurred when a device with PCI ID
    8086:10c8 was present on a system with a loaded ixgbe
    driver.

  - due to an aacraid driver regression, the kernel failed
    to boot when trying to load the aacraid driver and
    printed the following error message: 'aac_srb:
    aac_fib_send failed with status: 8195'.

  - due to an mpt driver regression, when RAID 1 was
    configured on Primergy systems with an LSI SCSI IME
    53C1020/1030 controller, the kernel panicked during
    boot.

  - the mpt driver produced a large number of extraneous
    debugging messages when performing a 'Host reset'
    operation.

  - due to a regression in the sym driver, the kernel
    panicked when a SCSI hot swap was performed using MCP18
    hardware.

  - all cores on a multi-core system now scale their
    frequencies in accordance with the policy set by the
    system's CPU frequency governor.

  - the netdump subsystem suffered from several stability
    issues. These are addressed in this updated kernel.

  - under certain conditions, the ext3 file system reported
    a negative count of used blocks.

  - reading /proc/self/mem incorrectly returned 'Invalid
    argument' instead of 'input/output error' due to a
    regression.

  - under certain conditions, the kernel panicked when a USB
    device was removed while the system was busy accessing
    the device.

  - a race condition in the kernel could have led to a
    kernel crash during the creation of a new process."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0811&L=scientific-linux-errata&T=0&P=1696
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb16bc1b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_cwe_id(189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-78.0.8.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-78.0.8.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
