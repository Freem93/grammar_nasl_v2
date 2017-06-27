#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(90393);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");

  script_name(english:"Scientific Linux Security Update : graphite2 on SL7.x x86_64");
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
"The following packages have been upgraded to a newer upstream version:
graphite2 (1.3.6).

Security Fix(es) :

  - Various vulnerabilities have been discovered in
    Graphite2. An attacker able to trick an unsuspecting
    user into opening specially crafted font files in an
    application using Graphite2 could exploit these flaws to
    cause the application to crash or, potentially, execute
    arbitrary code with the privileges of the application.
    (CVE-2016-1521, CVE-2016-1522, CVE-2016-1523,
    CVE-2016-1526)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1604&L=scientific-linux-errata&F=&S=&P=6103
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5928e087"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected graphite2, graphite2-debuginfo and / or
graphite2-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphite2-1.3.6-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphite2-debuginfo-1.3.6-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphite2-devel-1.3.6-1.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
