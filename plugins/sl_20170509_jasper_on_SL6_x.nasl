#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(100120);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2015-5203", "CVE-2015-5221", "CVE-2016-10248", "CVE-2016-10249", "CVE-2016-10251", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-2116", "CVE-2016-8654", "CVE-2016-8690", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8883", "CVE-2016-8884", "CVE-2016-8885", "CVE-2016-9262", "CVE-2016-9387", "CVE-2016-9388", "CVE-2016-9389", "CVE-2016-9390", "CVE-2016-9391", "CVE-2016-9392", "CVE-2016-9393", "CVE-2016-9394", "CVE-2016-9560", "CVE-2016-9583", "CVE-2016-9591", "CVE-2016-9600");

  script_name(english:"Scientific Linux Security Update : jasper on SL6.x, SL7.x i386/x86_64");
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

Multiple flaws were found in the way JasPer decoded JPEG 2000 image
files. A specially crafted file could cause an application using
JasPer to crash or, possibly, execute arbitrary code. (CVE-2016-8654,
CVE-2016-9560, CVE-2016-10249, CVE-2015-5203, CVE-2015-5221,
CVE-2016-1577, CVE-2016-8690, CVE-2016-8693, CVE-2016-8884,
CVE-2016-8885, CVE-2016-9262, CVE-2016-9591)

Multiple flaws were found in the way JasPer decoded JPEG 2000 image
files. A specially crafted file could cause an application using
JasPer to crash. (CVE-2016-1867, CVE-2016-2089, CVE-2016-2116,
CVE-2016-8691, CVE-2016-8692, CVE-2016-8883, CVE-2016-9387,
CVE-2016-9388, CVE-2016-9389, CVE-2016-9390, CVE-2016-9391,
CVE-2016-9392, CVE-2016-9393, CVE-2016-9394, CVE-2016-9583,
CVE-2016-9600, CVE-2016-10248, CVE-2016-10251)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1705&L=scientific-linux-errata&F=&S=&P=4039
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85f424a2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"jasper-1.900.1-21.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-debuginfo-1.900.1-21.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-devel-1.900.1-21.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-libs-1.900.1-21.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-utils-1.900.1-21.el6_9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-1.900.1-30.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-debuginfo-1.900.1-30.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-devel-1.900.1-30.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-libs-1.900.1-30.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-utils-1.900.1-30.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
