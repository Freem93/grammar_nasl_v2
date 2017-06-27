#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60216);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_name(english:"Scientific Linux Security Update : openafs on SL4.x i386/x86_64");
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
"Updated openafs that fixes several bugs. This is the same openafs that
is in Scientific Linux 4.5. Please remember that openafs is not
autoyumed by default. You will have to manually do a 'yum update' to
get the openafs update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=4398
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ad4b1b7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/25");
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
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-11.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-11.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-11.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.1.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-22.0.1.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.1.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.2.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-22.0.2.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.2.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-22.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.1.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-34.0.1.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.1.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.2.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-34.0.2.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.2.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-34.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-34.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.10.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.10.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.10.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.10.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.2.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.2.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.2.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.2.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.3.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.3.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.3.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.3.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.8.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.8.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.8.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.8.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-5.0.5.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-5.0.5.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.2.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-55.0.2.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-55.0.2.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.2.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.2.ELxenU-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.EL-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-55.ELhugemem-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-55.ELlargesmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.ELsmp-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.ELxenU-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-devel-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-client-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-compat-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-debug-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-devel-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kernel-source-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kpasswd-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-krb5-1.4.4-46.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-server-1.4.4-46.SL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
