#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61022);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-0430", "CVE-2011-0431");

  script_name(english:"Scientific Linux Security Update : openafs on SL4.x, SL5.x i386/x86_64");
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
"Double free vulnerability in the Rx server process in OpenAFS 1.4.14,
1.4.12, 1.4.7, and possibly other versions allows remote attackers to
cause a denial of service and execute arbitrary code via unknown
vectors. (CVE-2011-0430)

The afs_linux_lock function in afs/LINUX/osi_vnodeops.c in the kernel
module in OpenAFS 1.4.14, 1.4.12, 1.4.7, and possibly other versions
does not properly handle errors, which allows attackers to cause a
denial of service via unknown vectors. (CVE-2011-0431)

This update will also bring all the SL4 and SL5 openafs versions up to
the same version."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=2624
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f0f2749"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");
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
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-89.35.1.EL-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-89.35.1.ELhugemem-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-89.35.1.ELlargesmp-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-89.35.1.ELsmp-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-89.35.1.ELxenU-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-devel-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-client-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-compat-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-debug-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-devel-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kernel-source-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kpasswd-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-krb5-1.4.14-80.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-server-1.4.14-80.sl4")) flag++;

if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-238.9.1.el5-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-238.9.1.el5PAE-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-238.9.1.el5xen-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.14-80.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.14-80.sl5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
