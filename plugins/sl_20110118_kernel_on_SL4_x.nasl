#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60938);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3859", "CVE-2010-3876", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4242", "CVE-2010-4249");

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

  - A heap overflow flaw was found in the Linux kernel's
    Transparent Inter-Process Communication protocol (TIPC)
    implementation. A local, unprivileged user could use
    this flaw to escalate their privileges. (CVE-2010-3859,
    Important)

  - Missing sanity checks were found in gdth_ioctl_alloc()
    in the gdth driver in the Linux kernel. A local user
    with access to '/dev/gdth' on a 64-bit system could use
    these flaws to cause a denial of service or escalate
    their privileges. (CVE-2010-4157, Moderate)

  - A NULL pointer dereference flaw was found in the
    Bluetooth HCI UART driver in the Linux kernel. A local,
    unprivileged user could use this flaw to cause a denial
    of service. (CVE-2010-4242, Moderate)

  - A flaw was found in the Linux kernel's garbage collector
    for AF_UNIX sockets. A local, unprivileged user could
    use this flaw to trigger a denial of service
    (out-of-memory condition). (CVE-2010-4249, Moderate)

  - Missing initialization flaws were found in the Linux
    kernel. A local, unprivileged user could use these flaws
    to cause information leaks. (CVE-2010-3876,
    CVE-2010-4072, CVE-2010-4073, CVE-2010-4075,
    CVE-2010-4080, CVE-2010-4083, CVE-2010-4158, Low)

This update also fixes the following bugs :

  - A flaw was found in the Linux kernel where, if used in
    conjunction with another flaw that can result in a
    kernel Oops, could possibly lead to privilege
    escalation. It does not affect Red Hat Enterprise Linux
    4 as the sysctl panic_on_oops variable is turned on by
    default. However, as a preventive measure if the
    variable is turned off by an administrator, this update
    addresses the issue. (BZ#659568)

  - On Intel I/O Controller Hub 9 (ICH9) hardware, jumbo
    frame support is achieved by using page-based sk_buff
    buffers without any packet split. The entire frame data
    is copied to the page(s) rather than some to the
    skb->data area and some to the page(s) when performing a
    typical packet-split. This caused problems with the
    filtering code and frames were getting dropped before
    they were received by listening applications. This bug
    could eventually lead to the IP address being released
    and not being able to be re-acquired from DHCP if the
    MTU (Maximum Transfer Unit) was changed (for an affected
    interface using the e1000e driver). With this update,
    frames are no longer dropped and an IP address is
    correctly re-acquired after a previous release.
    (BZ#664667)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1101&L=scientific-linux-errata&T=0&P=903
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e85585d8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=659568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=664667"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/18");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.35.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.35.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
