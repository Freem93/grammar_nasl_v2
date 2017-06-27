#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(91537);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/06/09 15:35:16 $");

  script_cve_id("CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9653");

  script_name(english:"Scientific Linux Security Update : file on SL6.x i386/x86_64");
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
"Security Fix(es) :

  - Multiple flaws were found in the file regular expression
    rules for detecting various files. A remote attacker
    could use these flaws to cause file to consume an
    excessive amount of CPU. (CVE-2014-3538)

  - A denial of service flaw was found in the way file
    parsed certain Composite Document Format (CDF) files. A
    remote attacker could use this flaw to crash file via a
    specially crafted CDF file. (CVE-2014-3587)

  - Multiple flaws were found in the way file parsed
    Executable and Linkable Format (ELF) files. A remote
    attacker could use these flaws to cause file to crash,
    disclose portions of its memory, or consume an excessive
    amount of system resources. (CVE-2014-3710,
    CVE-2014-8116, CVE-2014-8117, CVE-2014-9620,
    CVE-2014-9653)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=850
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a45ea396"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"file-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-debuginfo-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-devel-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-libs-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"file-static-5.04-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-magic-5.04-30.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
