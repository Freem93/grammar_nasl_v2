#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(91081);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2015-2328", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8388", "CVE-2015-8391", "CVE-2016-3191");

  script_name(english:"Scientific Linux Security Update : pcre on SL7.x x86_64");
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

  - Multiple flaws were found in the way PCRE handled
    malformed regular expressions. An attacker able to make
    an application using PCRE process a specially crafted
    regular expression could use these flaws to cause the
    application to crash or, possibly, execute arbitrary
    code. (CVE-2015-8385, CVE-2016-3191, CVE-2015-2328,
    CVE-2015-3217, CVE-2015-5073, CVE-2015-8388,
    CVE-2015-8391, CVE-2015-8386)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1605&L=scientific-linux-errata&F=&S=&P=4584
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dd56b8f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcre-8.32-15.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcre-debuginfo-8.32-15.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcre-devel-8.32-15.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcre-static-8.32-15.el7_2.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcre-tools-8.32-15.el7_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
