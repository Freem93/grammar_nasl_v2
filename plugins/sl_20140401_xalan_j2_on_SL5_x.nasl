#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(73296);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/17 10:42:09 $");

  script_cve_id("CVE-2014-0107");

  script_name(english:"Scientific Linux Security Update : xalan-j2 on SL5.x, SL6.x i386/x86_64");
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
"It was found that the secure processing feature of Xalan-Java had
insufficient restrictions defined for certain properties and features.
A remote attacker able to provide Extensible Stylesheet Language
Transformations (XSLT) content to be processed by an application using
Xalan-Java could use this flaw to bypass the intended constraints of
the secure processing feature. Depending on the components available
in the classpath, this could lead to arbitrary remote code execution
in the context of the application server running the application that
uses Xalan- Java. (CVE-2014-0107)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1404&L=scientific-linux-errata&T=0&P=188
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b397ade2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/02");
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
if (rpm_check(release:"SL5", reference:"xalan-j2-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"SL5", reference:"xalan-j2-debuginfo-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"SL5", reference:"xalan-j2-demo-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"SL5", reference:"xalan-j2-javadoc-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"SL5", reference:"xalan-j2-manual-2.7.0-6jpp.2")) flag++;
if (rpm_check(release:"SL5", reference:"xalan-j2-xsltc-2.7.0-6jpp.2")) flag++;

if (rpm_check(release:"SL6", reference:"xalan-j2-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xalan-j2-demo-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xalan-j2-javadoc-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xalan-j2-manual-2.7.0-9.9.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"xalan-j2-xsltc-2.7.0-9.9.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
