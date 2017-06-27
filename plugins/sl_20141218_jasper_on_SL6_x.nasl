#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(80117);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/19 15:16:24 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-9029");

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
"Multiple off-by-one flaws, leading to heap-based buffer overflows,
were found in the way JasPer decoded JPEG 2000 image files. A
specially crafted file could cause an application using JasPer to
crash or, possibly, execute arbitrary code. (CVE-2014-9029)

A heap-based buffer overflow flaw was found in the way JasPer decoded
JPEG 2000 image files. A specially crafted file could cause an
application using JasPer to crash or, possibly, execute arbitrary
code. (CVE-2014-8138)

A double free flaw was found in the way JasPer parsed ICC color
profiles in JPEG 2000 image files. A specially crafted file could
cause an application using JasPer to crash or, possibly, execute
arbitrary code. (CVE-2014-8137)

All applications using the JasPer libraries must be restarted for the
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=3342
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76036159"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"jasper-1.900.1-16.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-debuginfo-1.900.1-16.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-devel-1.900.1-16.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-libs-1.900.1-16.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-utils-1.900.1-16.el6_6.2")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-1.900.1-26.el7_0.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-debuginfo-1.900.1-26.el7_0.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-devel-1.900.1-26.el7_0.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-libs-1.900.1-26.el7_0.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"jasper-utils-1.900.1-26.el7_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
