#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60810);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/03/14 14:55:46 $");

  script_cve_id("CVE-2010-0291", "CVE-2010-0622", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1436", "CVE-2010-1437", "CVE-2010-1641");

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
"This update fixes the following security issues :

  - multiple flaws were found in the mmap and mremap
    implementations. A local user could use these flaws to
    cause a local denial of service or escalate their
    privileges. (CVE-2010-0291, Important)

  - a NULL pointer dereference flaw was found in the Fast
    Userspace Mutexes (futexes) implementation. The unlock
    code path did not check if the futex value associated
    with pi_state->owner had been modified. A local user
    could use this flaw to modify the futex value, possibly
    leading to a denial of service or privilege escalation
    when the pi_state->owner pointer is dereferenced.
    (CVE-2010-0622, Important)

  - a NULL pointer dereference flaw was found in the Linux
    kernel Network File System (NFS) implementation. A local
    user on a system that has an NFS-mounted file system
    could use this flaw to cause a denial of service or
    escalate their privileges on that system.
    (CVE-2010-1087, Important)

  - a flaw was found in the sctp_process_unk_param()
    function in the Linux kernel Stream Control Transmission
    Protocol (SCTP) implementation. A remote attacker could
    send a specially crafted SCTP packet to an SCTP
    listening port on a target system, causing a kernel
    panic (denial of service). (CVE-2010-1173, Important)

  - a flaw was found in the Linux kernel Transparent
    Inter-Process Communication protocol (TIPC)
    implementation. If a client application, on a local
    system where the tipc module is not yet in network mode,
    attempted to send a message to a remote TIPC node, it
    would dereference a NULL pointer on the local system,
    causing a kernel panic (denial of service).
    (CVE-2010-1187, Important)

  - a buffer overflow flaw was found in the Linux kernel
    Global File System 2 (GFS2) implementation. In certain
    cases, a quota could be written past the end of a memory
    page, causing memory corruption, leaving the quota
    stored on disk in an invalid state. A user with write
    access to a GFS2 file system could trigger this flaw to
    cause a kernel crash (denial of service) or escalate
    their privileges on the GFS2 server. This issue can only
    be triggered if the GFS2 file system is mounted with the
    'quota=on' or 'quota=account' mount option.
    (CVE-2010-1436, Important)

  - a race condition between finding a keyring by name and
    destroying a freed keyring was found in the Linux kernel
    key management facility. A local user could use this
    flaw to cause a kernel panic (denial of service) or
    escalate their privileges. (CVE-2010-1437, Important)

  - a flaw was found in the link_path_walk() function in the
    Linux kernel. Using the file descriptor returned by the
    open() function with the O_NOFOLLOW flag on a
    subordinate NFS-mounted file system, could result in a
    NULL pointer dereference, causing a denial of service or
    privilege escalation. (CVE-2010-1088, Moderate)

  - a missing permission check was found in the
    gfs2_set_flags() function in the Linux kernel GFS2
    implementation. A local user could use this flaw to
    change certain file attributes of files, on a GFS2 file
    system, that they do not own. (CVE-2010-1641, Low)

Red Hat would like to thank Jukka Taimisto and Olli Jarva of
Codenomicon Ltd, Nokia Siemens Networks, and Wind River on behalf of
their customer, for responsibly reporting CVE-2010-1173; Mario
Mikocevic for responsibly reporting CVE-2010-1436; and Dan Rosenberg
for responsibly reporting CVE-2010-1641.

This update also fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=211
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed5addc0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/01");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-aufs-2.6.18-194.8.1.el5-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-aufs-2.6.18-194.8.1.el5PAE-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-aufs-2.6.18-194.8.1.el5xen-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-194.8.1.el5-1.55-1.SL")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ndiswrapper-2.6.18-194.8.1.el5PAE-1.55-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-194.8.1.el5xen-1.55-1.SL")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-xfs-2.6.18-194.8.1.el5-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-xfs-2.6.18-194.8.1.el5PAE-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-xfs-2.6.18-194.8.1.el5xen-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-194.8.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
