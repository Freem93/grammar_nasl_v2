#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61326);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/11/16 11:51:00 $");

  script_cve_id("CVE-2012-0217", "CVE-2012-2934");

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

  - It was found that the Xen hypervisor implementation as
    shipped with Scientific Linux 5 did not properly
    restrict the syscall return addresses in the sysret
    return path to canonical addresses. An unprivileged user
    in a 64-bit para-virtualized guest, that is running on a
    64-bit host that has an Intel CPU, could use this flaw
    to crash the host or, potentially, escalate their
    privileges, allowing them to execute arbitrary code at
    the hypervisor level. (CVE-2012-0217, Important)

  - It was found that guests could trigger a bug in earlier
    AMD CPUs, leading to a CPU hard lockup, when running on
    the Xen hypervisor implementation. An unprivileged user
    in a 64-bit para-virtualized guest could use this flaw
    to crash the host. Warning: After installing this
    update, hosts that are using an affected AMD CPU (refer
    to upstream bug #824966 for a list) will fail to boot.
    In order to boot such hosts, the new kernel parameter,
    allow_unsafe, can be used ('allow_unsafe=on'). This
    option should only be used with hosts that are running
    trusted guests, as setting it to 'on' reintroduces the
    flaw (allowing guests to crash the host).
    (CVE-2012-2934, Moderate)

Note: For Scientific Linux guests, only privileged guest users can
exploit the CVE-2012-0217 and CVE-2012-2934 issues.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1206&L=scientific-linux-errata&T=0&P=1832
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a86088a6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-308.8.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-308.8.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
