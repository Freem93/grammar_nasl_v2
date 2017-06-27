#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60442);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");

  script_name(english:"Scientific Linux Security Update : ruby on SL4.x, SL5.x i386/x86_64");
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
"Multiple integer overflows leading to a heap overflow were discovered
in the array- and string-handling code used by Ruby. An attacker could
use these flaws to crash a Ruby application or, possibly, execute
arbitrary code with the privileges of the Ruby application using
untrusted inputs in array or string operations. (CVE-2008-2376,
CVE-2008-2662, CVE-2008-2663, CVE-2008-2725, CVE-2008-2726)

It was discovered that Ruby used the alloca() memory allocation
function in the format (%) method of the String class without properly
restricting maximum string length. An attacker could use this flaw to
crash a Ruby application or, possibly, execute arbitrary code with the
privileges of the Ruby application using long, untrusted strings as
format strings. (CVE-2008-2664)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=803
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d40ad95e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
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
if (rpm_check(release:"SL4", reference:"irb-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-devel-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-docs-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-libs-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-mode-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-tcltk-1.8.1-7.el4_6.1")) flag++;

if (rpm_check(release:"SL5", reference:"ruby-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-devel-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-docs-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-irb-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-libs-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-mode-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-rdoc-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-ri-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-tcltk-1.8.5-5.el5_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
