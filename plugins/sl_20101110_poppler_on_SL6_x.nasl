#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60896);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 00:00:32 $");

  script_cve_id("CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");

  script_name(english:"Scientific Linux Security Update : poppler on SL6.x i386/x86_64");
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
"Two uninitialized pointer use flaws were discovered in poppler. An
attacker could create a malicious PDF file that, when opened, would
cause applications that use poppler (such as Evince) to crash or,
potentially, execute arbitrary code. (CVE-2010-3702, CVE-2010-3703)

An array index error was found in the way poppler parsed PostScript
Type 1 fonts embedded in PDF documents. An attacker could create a
malicious PDF file that, when opened, would cause applications that
use poppler (such as Evince) to crash or, potentially, execute
arbitrary code. (CVE-2010-3704)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=2095
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5bc571d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
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
if (rpm_check(release:"SL6", reference:"poppler-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-glib-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-glib-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-qt-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-qt-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-qt4-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-qt4-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"poppler-utils-0.12.4-3.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
