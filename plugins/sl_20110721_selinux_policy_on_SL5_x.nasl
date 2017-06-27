#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61093);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_name(english:"Scientific Linux Security Update : selinux-policy on SL5.x i386/x86_64");
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
"In accordance with the Scientific Linux errata policy, we are pushing
out this selinux-policy bug fix as a security errata
http://www.scientificlinux.org/documentation/faq/errata

The selinux-policy packages contain the rules that govern how confined
processes run on the system.

These updated selinux-policy packages include a number of bug fixes
and enhancements. Space precludes documenting all of these changes in
this advisory."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=549
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1496c9d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.scientificlinux.org/documentation/faq/errata"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
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
if (rpm_check(release:"SL5", reference:"selinux-policy-2.4.6-316.el5")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-devel-2.4.6-316.el5")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-minimum-2.4.6-316.el5")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-mls-2.4.6-316.el5")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-strict-2.4.6-316.el5")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-targeted-2.4.6-316.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
