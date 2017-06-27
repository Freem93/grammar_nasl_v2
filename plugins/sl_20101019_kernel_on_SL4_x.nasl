#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60871);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-2942", "CVE-2010-3067", "CVE-2010-3477");

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
"This update fixes the following security issues :

  - Information leak flaws were found in the Linux kernel
    Traffic Control Unit implementation. A local attacker
    could use these flaws to cause the kernel to leak kernel
    memory to user-space, possibly leading to the disclosure
    of sensitive information. (CVE-2010-2942, Moderate)

  - A flaw was found in the tcf_act_police_dump() function
    in the Linux kernel network traffic policing
    implementation. A data structure in
    tcf_act_police_dump() was not initialized properly
    before being copied to user-space. A local, unprivileged
    user could use this flaw to cause an information leak.
    (CVE-2010-3477, Moderate)

  - A missing upper bound integer check was found in the
    sys_io_submit() function in the Linux kernel
    asynchronous I/O implementation. A local, unprivileged
    user could use this flaw to cause an information leak.
    (CVE-2010-3067, Low)

This update also fixes the following bugs :

  - When two systems using bonding devices in the adaptive
    load balancing (ALB) mode communicated with each other,
    an endless loop of ARP replies started between these two
    systems due to a faulty MAC address update. With this
    update, the MAC address update no longer creates
    unneeded ARP replies. (BZ#629239)

  - When running the Connectathon NFS Testsuite with certain
    clients and Scientific Linux 4.8 as the server,
    nfsvers4, lock, and test2 failed the Connectathon test.
    (BZ#625535)

  - For UDP/UNIX domain sockets, due to insufficient memory
    barriers in the network code, a process sleeping in
    select() may have missed notifications about new data.
    In rare cases, this bug may have caused a process to
    sleep forever. (BZ#640117)

  - In certain situations, a bug found in either the HTB or
    TBF network packet schedulers in the Linux kernel could
    have caused a kernel panic when using Broadcom network
    cards with the bnx2 driver. (BZ#624363)

  - Previously, allocating fallback cqr for DASD
    reserve/release IOCTLs failed because it used the memory
    pool of the respective device. This update preallocates
    sufficient memory for a single reserve/release request.
    (BZ#626828)

  - In some situations a bug prevented 'force online'
    succeeding for a DASD device. (BZ#626827)

  - Using the 'fsstress' utility may have caused a kernel
    panic. (BZ#633968)

  - This update introduces additional stack guard patches.
    (BZ#632515)

  - A bug was found in the way the megaraid_sas driver
    handled physical disks and management IOCTLs. All
    physical disks were exported to the disk layer, allowing
    an oops in megasas_complete_cmd_dpc() when completing
    the IOCTL command if a timeout occurred. (BZ#631903)

  - Previously, a warning message was returned when a large
    amount of messages was passed through netconsole and a
    considerable amount of network load was added. With this
    update, the warning message is no longer displayed.
    (BZ#637729)

  - Executing a large 'dd' command (1 to 5GB) on an iSCSI
    device with the qla3xxx driver caused a system crash due
    to the incorrect storing of a private data structure.
    With this update, the size of the stored data structure
    is checked and the system crashes no longer occur.
    (BZ#624364)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1010&L=scientific-linux-errata&T=0&P=1870
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c905f6f2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=624363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=624364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=625535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=626827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=626828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=629239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=631903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=632515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=633968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=637729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=640117"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.31.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
