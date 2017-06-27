#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97378);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/24 15:07:16 $");

  script_cve_id("CVE-2016-6136", "CVE-2016-9555");

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
"Security Fix(es) :

  - When creating audit records for parameters to executed
    children processes, an attacker can convince the Linux
    kernel audit subsystem can create corrupt records which
    may allow an attacker to misrepresent or evade logging
    of executing commands. (CVE-2016-6136, Moderate)

  - A flaw was found in the Linux kernel's implementation of
    the SCTP protocol. A remote attacker could trigger an
    out-of-bounds read with an offset of up to 64kB
    potentially causing the system to crash. (CVE-2016-9555,
    Moderate)

Bug Fix(es) :

  - The qlnic driver previously attempted to fetch pending
    transmission descriptors before all writes were
    complete, which lead to firmware hangs. With this
    update, the qlcnic driver has been fixed to complete all
    writes before the hardware fetches any pending
    transmission descriptors. As a result, the firmware no
    longer hangs with the qlcnic driver.

  - Previously, when a NFS share was mounted, the
    file-system (FS) cache was incorrectly enabled even when
    the '-o fsc' option was not used in the mount command.
    Consequently, the cachefilesd service stored files in
    the NFS share even when not instructed to by the user.
    With this update, NFS does not use the FS cache if not
    instructed by the '-o fsc' option. As a result, NFS no
    longer enables caching if the '-o fsc' option is not
    used.

  - Previously, an NFS client and NFS server got into a NFS4
    protocol loop involving a WRITE action and a
    NFS4ERR_EXPIRED response when the current_fileid counter
    got to the wraparound point by overflowing the value of
    32 bits. This update fixes the NFS server to handle the
    current_fileid wraparound. As a result, the described
    NFS4 protocol loop no longer occurs.

  - Previously, certain configurations of the Hewlett
    Packard Smart Array (HPSA) devices caused hardware to be
    set offline incorrectly when the HPSA driver was
    expected to wait for existing I/O operations to
    complete. Consequently, a kernel panic occurred. This
    update prevents the described problem. As a result, the
    kernel panic no longer occurs.

  - Previously, memory corruption by copying data into the
    wrong memory locations sometimes occurred, because the
    __copy_tofrom_user() function was returning incorrect
    values. This update fixes the __copy_tofrom_user()
    function so that it no longer returns larger values than
    the number of bytes it was asked to copy. As a result,
    memory corruption no longer occurs in he described
    scenario.

  - Previously, guest virtual machines (VMs) on a Hyper-V
    server cluster got in some cases rebooted during the
    graceful node failover test, because the host kept
    sending heartbeat packets independently of guests
    responding to them. This update fixes the bug by
    properly responding to all the heartbeat messages in the
    queue, even if they are pending. As a result, guest VMs
    no longer get rebooted under the described
    circumstances.

  - When the 'punching hole' feature of the fallocate
    utility was used on an ext4 file system inode with
    extent depth of 1, the extent tree of the inode
    sometimes became corrupted. With this update, the
    underlying source code has been fixed, and extent tree
    corruption no longer occurs in the described situation."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1702&L=scientific-linux-errata&F=&S=&P=4925
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00cce47f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-642.15.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
