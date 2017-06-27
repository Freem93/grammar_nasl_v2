#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61361);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-2744", "CVE-2012-2745");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - A NULL pointer dereference flaw was found in the
    nf_ct_frag6_reasm() function in the Linux kernel's
    netfilter IPv6 connection tracking implementation. A
    remote attacker could use this flaw to send specially
    crafted packets to a target system that is using IPv6
    and also has the nf_conntrack_ipv6 kernel module loaded,
    causing it to crash. (CVE-2012-2744, Important)

  - A flaw was found in the way the Linux kernel's key
    management facility handled replacement session keyrings
    on process forks. A local, unprivileged user could use
    this flaw to cause a denial of service. (CVE-2012-2745,
    Moderate)

This update also fixes the following bugs :

  - Previously introduced firmware files required for new
    Realtek chipsets contained an invalid prefix
    ('rtl_nic_') in the file names, for example
    '/lib/firmware/rtl_nic/rtl_nic_rtl8168d-1.fw'. This
    update corrects these file names. For example, the
    aforementioned file is now correctly named
    '/lib/firmware/rtl_nic/rtl8168d-1.fw'.

  - This update blacklists the ADMA428M revision of the 2GB
    ATA Flash Disk device. This is due to data corruption
    occurring on the said device when the Ultra-DMA 66
    transfer mode is used. When the
    'libata.force=5:pio0,6:pio0' kernel parameter is set,
    the aforementioned device works as expected.

  - On Scientific Linux 6, mounting an NFS export from a
    server running Windows Server 2012 Release Candidate
    returned the NFS4ERR_MINOR_VERS_MISMATCH error because
    Windows Server 2012 Release Candidate supports NFSv4.1
    only. Scientific Linux 6 did not properly handle the
    returned error and did not fall back to using NFSv3,
    which caused the mount operation to fail. With this
    update, when the NFS4ERR_MINOR_VERS_MISMATCH error is
    returned, the mount operation properly falls back to
    using NFSv3 and no longer fails.

  - On ext4 file systems, when fallocate() failed to
    allocate blocks due to the ENOSPC condition (no space
    left on device) for a file larger than 4 GB, the size of
    the file became corrupted and, consequently, caused file
    system corruption. This was due to a missing cast
    operator in the 'ext4_fallocate()' function. With this
    update, the underlying source code has been modified to
    address this issue, and file system corruption no longer
    occurs.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=6268
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ce1dd2e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-279.1.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
