#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60258);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-4573");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x, SL4.x, SL3.x i386/x86_64");
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
"A flaw was found in the IA32 system call emulation provided on AMD64
and Intel 64 platforms. An improperly validated 64-bit value could be
stored in the %RAX register, which could trigger an out-of-bounds
system call table access. An untrusted local user could exploit this
flaw to run code in the kernel (ie a root privilege escalation).
(CVE-2007-4573).

Please Note: Kernel's and their dependencies do *NOT* get autoyumed.
You have to update them by hand by simply typing 'yum update'"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0709&L=scientific-linux-errata&T=0&P=2259
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2fa7335"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/27");
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
if (rpm_check(release:"SL3", reference:"kernel-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-doc-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-unsupported-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-source-2.4.21-52.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-unsupported-2.4.21-52.EL")) flag++;

if (rpm_check(release:"SL4", reference:"kernel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-55.0.9.EL")) flag++;

if (rpm_check(release:"SL5", reference:"kernel-2.6.18-8.1.14.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-8.1.14.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-8.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-8.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-8.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-8.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-8.1.14.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-8.1.14.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
