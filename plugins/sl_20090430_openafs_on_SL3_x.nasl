#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60579);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-1250", "CVE-2009-1251");

  script_name(english:"Scientific Linux Security Update : openafs on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"An attacker with control of a fileserver, or the ability to forge RX
packets, can crash the cache manager, and hence the kernel, of
affected Linux AFS clients. (CVE-2009-1250)

An attacker with control of a fileserver, or the ability to forge RX
packets, can crash the cache manager, and hence the kernel, of any
Unix AFS client. It may be possible for an attacker to cause the
kernel to execute arbitrary code. (CVE-2009-1251)

The Scientific Linux Team has backported the patches to the stable
version of openafs for SL3, SL4 and SL5.

openafs must be restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0904&L=scientific-linux-errata&T=0&P=3574
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?699e6350"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/30");
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
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-52.EL-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-52.ELsmp-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-53.EL-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-53.ELsmp-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-57.EL-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-57.ELsmp-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-58.EL-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-module-openafs-2.4.21-58.ELsmp-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-client-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-compat-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-debug-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-devel-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-kernel-source-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-kpasswd-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-krb5-1.2.13-15.18.SL")) flag++;
if (rpm_check(release:"SL3", reference:"openafs-server-1.2.13-15.18.SL")) flag++;

if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-11.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-11.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-11.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.1.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-22.0.1.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.1.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.2.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-22.0.2.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.0.2.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-22.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-22.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.1.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-34.0.1.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.1.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.2.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-34.0.2.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.0.2.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-34.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-34.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-34.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.10.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.10.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.10.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.10.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.2.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.2.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.2.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.2.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.3.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.3.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.3.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.3.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.8.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.0.8.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.0.8.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.0.8.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-42.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-42.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-42.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-5.0.5.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-5.0.5.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.12.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-55.0.12.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-55.0.12.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.12.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.12.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.2.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-55.0.2.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-55.0.2.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.2.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.2.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.6.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-55.0.6.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-55.0.6.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.6.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.6.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.9.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-55.0.9.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-55.0.9.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.9.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.0.9.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-55.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-55.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-55.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.1.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-67.0.1.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-67.0.1.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.1.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.1.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.15.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-67.0.15.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-67.0.15.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.15.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.15.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.20.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-67.0.20.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-67.0.20.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.20.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.20.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.22.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-67.0.22.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-67.0.22.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.22.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.22.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.4.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-67.0.4.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-67.0.4.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.4.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.4.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.7.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-67.0.7.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-67.0.7.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.7.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.0.7.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-67.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-67.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-67.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.1.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-78.0.1.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-78.0.1.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.1.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.1.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.13.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-78.0.13.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-78.0.13.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.13.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.13.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.17.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-78.0.17.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-78.0.17.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.17.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.17.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.5.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-78.0.5.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-78.0.5.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.5.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.5.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.8.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-78.0.8.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-78.0.8.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.8.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.0.8.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.EL-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-module-openafs-2.6.9-78.ELhugemem-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-module-openafs-2.6.9-78.ELlargesmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.ELsmp-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-module-openafs-2.6.9-78.ELxenU-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-authlibs-devel-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-client-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-compat-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-debug-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-devel-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kernel-source-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-kpasswd-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-krb5-1.4.7-68.2.SL4")) flag++;
if (rpm_check(release:"SL4", reference:"openafs-server-1.4.7-68.2.SL4")) flag++;

if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.1.1.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-128.1.1.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.1.1.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.1.6.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-128.1.6.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.1.6.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-128.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-128.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.13.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.1.13.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.13.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.14.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.1.14.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.14.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.19.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.1.19.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.19.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.21.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.1.21.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.21.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.4.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.1.4.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.4.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.6.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.1.6.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.6.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.10.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.10.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.10.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.14.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.14.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.14.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.15.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.15.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.15.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.3.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.3.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.3.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.4.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.4.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.4.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.6.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.6.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.6.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.8.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-8.1.8.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-8.1.8.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.1.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.1.1.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.1.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.10.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.1.10.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.10.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.13.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.1.13.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.13.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.17.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.1.17.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.17.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.18.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.1.18.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.18.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.22.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.1.22.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.22.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.6.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.1.6.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.1.6.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.el5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-92.el5PAE-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-92.el5xen-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.7-68.2.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.7-68.2.SL5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
