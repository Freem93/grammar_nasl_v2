#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60461);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

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
"These updated packages fix the following bugs :

  - the GNU libc stub resolver is a minimal resolver that
    works with Domain Name System (DNS) servers to satisfy
    requests from applications for names. The GNU libc stub
    resolver did not specify a source UDP port, and
    therefore used predictable port numbers. This could have
    make DNS spoofing attacks easier.

The Linux kernel has been updated to implement random UDP source ports
where none are specified by an application. This allows applications,
such as those using the GNU libc stub resolver, to use random UDP
source ports, helping to make DNS spoofing attacks harder.

  - A set of patches detailed as 'sys_times: Fix system
    unresponsiveness during many concurrent invocation of
    sys_times()' and 'Minor code cleanup to sys_times()
    call' introduced regression which caused a kernel panic
    under high load. These patches were reverted in the
    current release.

  - A process could hang in an uninterruptible state while
    accessing application data files due to race condition
    in asynchronous direct I/O system calls.

  - USB devices would not be detected on a PowerEdge R805
    system. USB devices are now able to be detected on the
    aforementioned system with this update.

Further, these updated packages add the following enhancement :

  - Added HDMI support for AMD ATI chipsets RS780, RV610,
    RV620, RV630, RV635, RV670 and RV770."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0808&L=scientific-linux-errata&T=0&P=935
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99d87381"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/06");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-78.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-78.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
