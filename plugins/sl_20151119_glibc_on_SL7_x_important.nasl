#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87638);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/29 14:44:44 $");

  script_cve_id("CVE-2015-5277");

  script_name(english:"Scientific Linux Security Update : glibc on SL7.x x86_64_important");
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
"It was discovered that the nss_files backend for the Name Service
Switch in glibc would return incorrect data to applications or corrupt
the heap (depending on adjacent heap contents) in certain cases. A
local attacker could potentially use this flaw to escalate their
privileges. (CVE-2015-5277)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=7709
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0483503"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-common-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-common-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-devel-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-headers-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-static-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-utils-2.17-106.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nscd-2.17-106.el7_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
