#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63677);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/24 13:51:03 $");

  script_cve_id("CVE-2012-1568", "CVE-2012-4444", "CVE-2012-5515");

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

  - It was found that the Xen hypervisor implementation did
    not perform range checking on the guest provided values
    in multiple hypercalls. A privileged guest user could
    use this flaw to trigger long loops, leading to a denial
    of service (Xen hypervisor hang). (CVE-2012-5515,
    Moderate)

  - It was found that when running a 32-bit binary that uses
    a large number of shared libraries, one of the libraries
    would always be loaded at a predictable address in
    memory. An attacker could use this flaw to bypass the
    Address Space Layout Randomization (ASLR) security
    feature. (CVE-2012-1568, Low)

  - A flaw was found in the way the Linux kernel's IPv6
    implementation handled overlapping, fragmented IPv6
    packets. A remote attacker could potentially use this
    flaw to bypass protection mechanisms (such as a firewall
    or intrusion detection system (IDS)) when sending
    network packets to a target system. (CVE-2012-4444, Low)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=3081
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1406b944"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-348.1.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-348.1.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
