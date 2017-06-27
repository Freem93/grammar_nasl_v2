#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60181);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1592", "CVE-2007-1861", "CVE-2007-2172", "CVE-2007-2242");

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
"These new kernel packages contain fixes for the following security
issues :

  - a flaw in the handling of IPv6 type 0 routing headers
    that allowed remote users to cause a denial of service
    that led to a network amplification between two routers
    (CVE-2007-2242, Important).

  - a flaw in the nfnetlink_log netfilter module that
    allowed a local user to cause a denial of service
    (CVE-2007-1496, Important).

  - a flaw in the flow list of listening IPv6 sockets that
    allowed a local user to cause a denial of service
    (CVE-2007-1592, Important).

  - a flaw in the handling of netlink messages that allowed
    a local user to cause a denial of service (infinite
    recursion) (CVE-2007-1861, Important).

  - a flaw in the IPv4 forwarding base that allowed a local
    user to cause an out-of-bounds access (CVE-2007-2172,
    Important).

  - a flaw in the nf_conntrack netfilter module for IPv6
    that allowed remote users to bypass certain netfilter
    rules using IPv6 fragments (CVE-2007-1497, Moderate).

In addition to the security issues described above, fixes for the
following have been included :

  - a regression in ipv6 routing.

  - an error in memory initialization that caused gdb to
    output inaccurate backtraces on ia64.

  - the nmi watchdog timeout was updated from 5 to 30
    seconds.

  - a flaw in distributed lock management that could result
    in errors during virtual machine migration.

  - an omitted include in kernel-headers that led to compile
    failures for some packages."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0705&L=scientific-linux-errata&T=0&P=2287
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83d833e8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/16");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-doc-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-8.1.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-8.1.4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
