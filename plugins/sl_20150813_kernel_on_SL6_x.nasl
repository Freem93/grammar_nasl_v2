#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85397);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/09/01 13:24:51 $");

  script_cve_id("CVE-2015-5364", "CVE-2015-5366");

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
"Two flaws were found in the way the Linux kernel's networking
implementation handled UDP packets with incorrect checksum values. A
remote attacker could potentially use these flaws to trigger an
infinite loop in the kernel, resulting in a denial of service on the
system, or cause a denial of service in applications using the edge
triggered epoll functionality. (CVE-2015-5364, CVE-2015-5366,
Important)

This update also fixes the following bugs :

  - When removing a directory, and a reference was held to
    that directory by a reference to a negative child
    dentry, the directory dentry was previously not killed.
    In addition, once the negative child dentry was killed,
    an unlinked and unused dentry was present in the cache.
    As a consequence, deadlock could be caused by forcing
    the dentry eviction while the file system in question
    was frozen. With this update, all unused dentries are
    unhashed and evicted just after a successful directory
    removal, which avoids the deadlock, and the system no
    longer hangs in the aforementioned scenario.

  - Due to the broken s_umount lock ordering, a race
    condition occurred when an unlinked file was closed and
    the sync (or syncfs) utility was run at the same time.
    As a consequence, deadlock occurred on a frozen file
    system between sync and a process trying to unfreeze the
    file system. With this update, sync (or syncfs) is
    skipped on a frozen file system, and deadlock no longer
    occurs in the aforementioned situation.

  - Previously, in the scenario when a file was opened by
    file handle (fhandle) with its dentry not present in
    dcache ('cold dcache') and then making use of the
    unlink() and close() functions, the inode was not freed
    upon the close() system call. As a consequence, the
    iput() final was delayed indefinitely. A patch has been
    provided to fix this bug, and the inode is now freed as
    expected.

  - Due to a corrupted Executable and Linkable Format (ELF)
    header in the /proc/vmcore file, the kdump utility
    failed to provide any information. The underlying source
    code has been patched, and kdump now provides debuging
    information for kernel crashes as intended.

  - Previously, running the multipath request queue caused
    regressions in cases where paths failed regularly under
    I/O load. This regression manifested as I/O stalls that
    exceeded 300 seconds. This update reverts the changes
    aimed to reduce running the multipath request queue
    resulting in I/O stalls completing in a timely manner.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=14855
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5cd0e07"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/14");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-573.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-573.3.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
