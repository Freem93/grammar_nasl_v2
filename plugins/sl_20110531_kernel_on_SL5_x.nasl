#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61059);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2011-0726", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1163", "CVE-2011-1166", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1494", "CVE-2011-1577", "CVE-2011-1763");

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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - A flaw in the dccp_rcv_state_process() function could
    allow a remote attacker to cause a denial of service,
    even when the socket was already closed. (CVE-2011-1093,
    Important)

  - Multiple buffer overflow flaws were found in the Linux
    kernel's Management Module Support for Message Passing
    Technology (MPT) based controllers. A local,
    unprivileged user could use these flaws to cause a
    denial of service, an information leak, or escalate
    their privileges. (CVE-2011-1494, CVE-2011-1495,
    Important)

  - A missing validation of a null-terminated string data
    structure element in the bnep_sock_ioctl() function
    could allow a local user to cause an information leak or
    a denial of service. (CVE-2011-1079, Moderate)

  - Missing error checking in the way page tables were
    handled in the Xen hypervisor implementation could allow
    a privileged guest user to cause the host, and the
    guests, to lock up. (CVE-2011-1166, Moderate)

  - A flaw was found in the way the Xen hypervisor
    implementation checked for the upper boundary when
    getting a new event channel port. A privileged guest
    user could use this flaw to cause a denial of service or
    escalate their privileges. (CVE-2011-1763, Moderate)

  - The start_code and end_code values in '/proc/[pid]/stat'
    were not protected. In certain scenarios, this flaw
    could be used to defeat Address Space Layout
    Randomization (ASLR). (CVE-2011-0726, Low)

  - A missing initialization flaw in the
    sco_sock_getsockopt() function could allow a local,
    unprivileged user to cause an information leak.
    (CVE-2011-1078, Low)

  - A missing validation of a null-terminated string data
    structure element in the do_replace() function could
    allow a local user who has the CAP_NET_ADMIN capability
    to cause an information leak. (CVE-2011-1080, Low)

  - A buffer overflow flaw in the DEC Alpha OSF partition
    implementation in the Linux kernel could allow a local
    attacker to cause an information leak by mounting a disk
    that contains specially crafted partition tables.
    (CVE-2011-1163, Low)

  - Missing validations of null-terminated string data
    structure elements in the do_replace(),
    compat_do_replace(), do_ipt_get_ctl(),
    do_ip6t_get_ctl(), and do_arpt_get_ctl() functions could
    allow a local user who has the CAP_NET_ADMIN capability
    to cause an information leak. (CVE-2011-1170,
    CVE-2011-1171, CVE-2011-1172, Low)

  - A heap overflow flaw in the Linux kernel's EFI GUID
    Partition Table (GPT) implementation could allow a local
    attacker to cause a denial of service by mounting a disk
    that contains specially crafted partition tables.
    (CVE-2011-1577, Low)

This update also fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=1636
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4741efc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-238.12.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-238.12.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
