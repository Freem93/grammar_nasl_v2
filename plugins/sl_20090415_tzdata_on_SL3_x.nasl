#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60566);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_name(english:"Scientific Linux Security Update : tzdata on SL3.x, SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updated package addresses the following changes to Daylight
Saving Time (DST) observations :

  - Morocco will observe DST from 2009-06-01 00:00 to
    2009-08-21 00:00.

  - Tunisia will not observe DST this year.

  - Syria started DST on 2009-03-27 00:00 this year.

  - Cuba started DST at midnight between 2009-03-07 and
    2009-03-08.

  - the Province of San Luis, Argentina, went to UTC-04:00
    on 2009-03-15.

  - Palestine started DST on 2009-03-26 and end 2009-09-27.

  - Pakistan will observe DST between 2009-04-15 and,
    probably, 2009-11-01.

  - Egypt ends DST on 2009-09-24.

All users, especially those in locales affected by these time changes
and users interacting with people or systems in the affected locales,
are advised to upgrade to this updated package, which adds these
enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0904&L=scientific-linux-errata&T=0&P=1710
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b9b85b9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/15");
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
if (rpm_check(release:"SL3", reference:"tzdata-2009f-1.el3")) flag++;

if (rpm_check(release:"SL4", reference:"tzdata-2009f-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"tzdata-2009f-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
