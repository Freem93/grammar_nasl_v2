#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76782);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/25 10:46:37 $");

  script_cve_id("CVE-2014-2678", "CVE-2014-4021");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"  - A NULL pointer dereference flaw was found in the
    rds_iw_laddr_check() function in the Linux kernel's
    implementation of Reliable Datagram Sockets (RDS). A
    local, unprivileged user could use this flaw to crash
    the system. (CVE-2014-2678, Moderate)

  - It was found that the Xen hypervisor implementation did
    not properly clean memory pages previously allocated by
    the hypervisor. A privileged guest user could
    potentially use this flaw to read data relating to other
    guests or the hypervisor itself. (CVE-2014-4021,
    Moderate)

This update also fixes the following bugs :

  - A bug in the journaling block device (jbd and jbd2) code
    could, under certain circumstances, trigger a BUG_ON()
    assertion and result in a kernel oops. This happened
    when an application performed an extensive number of
    commits to the journal of the ext3 file system and there
    was no currently active transaction while synchronizing
    the file's in-core state. This problem has been resolved
    by correcting respective test conditions in the jbd and
    jbd2 code.

  - After a statically defined gateway became unreachable
    and its corresponding neighbor entry entered a FAILED
    state, the gateway stayed in the FAILED state even after
    it became reachable again. As a consequence, traffic was
    not routed through that gateway. This update allows
    probing such a gateway automatically so that the traffic
    can be routed through this gateway again once it becomes
    reachable.

  - Due to an incorrect condition check in the IPv6 code,
    the ipv6 driver was unable to correctly assemble
    incoming packet fragments, which resulted in a high IPv6
    packet loss rate. This update fixes the said check for a
    fragment overlap and ensures that incoming IPv6 packet
    fragments are now processed as expected.

  - Recent changes in the d_splice_alias() function
    introduced a bug that allowed d_splice_alias() to return
    a dentry from a different directory than the directory
    being looked up. As a consequence in cluster
    environment, a kernel panic could be triggered when a
    directory was being removed while a concurrent
    cross-directory operation was performed on this
    directory on another cluster node. This update avoids
    the kernel panic in this situation by correcting the
    search logic in the d_splice_alias() function so that
    the function can no longer return a dentry from an
    incorrect directory.

  - The NFSv4 server did not handle multiple OPEN operations
    to the same file separately, which could cause the NFSv4
    client to repeatedly send CLOSE requests with the same
    state ID, even though the NFS server rejected the
    request with an NFS4ERR_OLD_STATEID (10024) error code.
    This update ensures that the NFSv4 client no longer
    re-sends the same CLOSE request after receiving
    NFS4ERR_OLD_STATEID.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1407&L=scientific-linux-errata&T=0&P=2150
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfaff618"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-371.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-371.11.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
