#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62432);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/10/05 10:55:01 $");

  script_name(english:"Scientific Linux Security Update : tzdata enhancement update on SL5.x, SL6.x i386/x86_64");
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
"This update adds the following enhancements :

  - Daylight saving time in Fiji will start at 2:00 a.m. on
    Sunday, 21st October 2012, and end at 3 am on Sunday,
    20th January 2013.

  - Tokelau was listed in an incorrect time zone for as long
    as the Zoneinfo project was in existence. The actual
    zone was supposed to be GMT-11 hours before Tokelau was
    moved to the other side of the International Date Line
    at the end of year 2011. The local time in Tokelau is
    now GMT+13.

This update has been placed in the security tree to avoid timezone
related problems such as ntp sync errors."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1210&L=scientific-linux-errata&T=0&P=1223
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bafb683"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata and / or tzdata-java packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/05");
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
if (rpm_check(release:"SL5", reference:"tzdata-2012f-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tzdata-java-2012f-1.el5")) flag++;

if (rpm_check(release:"SL6", reference:"tzdata-2012f-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tzdata-java-2012f-1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
