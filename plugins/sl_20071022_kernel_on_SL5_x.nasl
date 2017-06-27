#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60272);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-3105", "CVE-2007-3380", "CVE-2007-3513", "CVE-2007-3731", "CVE-2007-3848", "CVE-2007-3850", "CVE-2007-4133", "CVE-2007-4308", "CVE-2007-4574");

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

  - A flaw was found in the backported stack unwinder fixes
    in Red Hat Enterprise Linux 5. On AMD64 and Intel 64
    platforms, a local user could trigger this flaw and
    cause a denial of service. (CVE-2007-4574, Important)

  - A flaw was found in the handling of process death
    signals. This allowed a local user to send arbitrary
    signals to the suid-process executed by that user. A
    successful exploitation of this flaw depends on the
    structure of the suid-program and its signal handling.
    (CVE-2007-3848, Important)

  - A flaw was found in the Distributed Lock Manager (DLM)
    in the cluster manager. This allowed a remote user who
    is able to connect to the DLM port to cause a denial of
    service. (CVE-2007-3380, Important)

  - A flaw was found in the aacraid SCSI driver. This
    allowed a local user to make ioctl calls to the driver
    which should otherwise be restricted to privileged
    users. (CVE-2007-4308, Moderate)

  - A flaw was found in the prio_tree handling of the
    hugetlb support that allowed a local user to cause a
    denial of service. This only affected kernels with
    hugetlb support. (CVE-2007-4133, Moderate)

  - A flaw was found in the eHCA driver on PowerPC
    architectures that allowed a local user to access 60k of
    physical address space. This address space could contain
    sensitive information. (CVE-2007-3850, Moderate)

  - A flaw was found in ptrace support that allowed a local
    user to cause a denial of service via a NULL pointer
    dereference. (CVE-2007-3731, Moderate)

  - A flaw was found in the usblcd driver that allowed a
    local user to cause a denial of service by writing data
    to the device node. To exploit this issue, write access
    to the device node was needed. (CVE-2007-3513, Moderate)

  - A flaw was found in the random number generator
    implementation that allowed a local user to cause a
    denial of service or possibly gain privileges. If the
    root user raised the default wakeup threshold over the
    size of the output pool, this flaw could be exploited.
    (CVE-2007-3105, Low)

In addition to the security issues described above, several bug fixes
preventing possible system crashes and data corruption were also
included."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0710&L=scientific-linux-errata&T=0&P=1849
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a23cf847"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(16, 20, 119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/22");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-fuse-2.6.18-8.1.15.el5-2.6.3-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-module-fuse-2.6.18-8.1.15.el5-2.6.3-1.SL")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-fuse-2.6.18-8.1.15.el5PAE-2.6.3-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-fuse-2.6.18-8.1.15.el5xen-2.6.3-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-module-fuse-2.6.18-8.1.15.el5xen-2.6.3-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-8.1.15.el5-1.2.0-1.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ipw3945-2.6.18-8.1.15.el5PAE-1.2.0-1.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-8.1.15.el5xen-1.2.0-1.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-8.1.15.el5-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-2.6.18-8.1.15.el5PAE-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-8.1.15.el5xen-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-8.1.15.el5-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.18-8.1.15.el5PAE-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-8.1.15.el5xen-0.9.3.1-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-8.1.15.el5-1.41-1.SL")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ndiswrapper-2.6.18-8.1.15.el5PAE-1.41-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-8.1.15.el5xen-1.41-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.15.el5-1.4.4-42.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.15.el5PAE-1.4.4-42.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.15.el5xen-1.4.4-42.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-r1000-2.6.18-8.1.15.el5-1.05-1.sl")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-r1000-2.6.18-8.1.15.el5PAE-1.05-1.sl")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-r1000-2.6.18-8.1.15.el5xen-1.05-1.sl")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-8.1.15.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
