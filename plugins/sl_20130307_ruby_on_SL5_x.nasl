#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65093);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2013-1821");

  script_name(english:"Scientific Linux Security Update : ruby on SL5.x i386/x86_64");
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
"It was discovered that Ruby's REXML library did not properly restrict
XML entity expansion. An attacker could use this flaw to cause a
denial of service by tricking a Ruby application using REXML to read
text nodes from specially crafted XML content, which will result in
REXML consuming large amounts of system memory. (CVE-2013-1821)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=2844
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a4b072c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"ruby-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-debuginfo-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-devel-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-docs-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-irb-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-libs-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-mode-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-rdoc-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-ri-1.8.5-29.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-tcltk-1.8.5-29.el5_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
