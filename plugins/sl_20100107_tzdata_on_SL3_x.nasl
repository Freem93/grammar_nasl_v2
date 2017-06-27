#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60720);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_name(english:"Scientific Linux Security Update : tzdata on SL3.x, SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The tzdata package contains data files with rules for various time
zones around the world.

This updated package addresses the following changes to Daylight
Saving Time (DST) observations and to time zones :

  - Bangladesh changed their clock back to Standard Time on
    December 31, 2009. (BZ#550570, BZ#551446, BZ#552300)

  - Argentina did not enter DST on October 18, 2009.

  - San Luis changed its time zone from UTC-4 to UTC-3 on
    October 11th.

  - the end of Daylight Saving Time in Syria changed to the
    last Friday in October.

  - Kemerovo Oblast in Russia will change its time zone on
    March 28, 2010 to the newly-created Asia/Novokuznetsk
    zone.

  - local times for three Australian research stations in
    Antarctica were updated.

  - Fiji plans to re-introduce DST from November 29th, 2009
    to April 25th, 2010.

All users, especially those in the locale affected by these time
changes and users interacting with people or systems in the affected
locale, are advised to upgrade to this updated package, which adds
these enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1001&L=scientific-linux-errata&T=0&P=445
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc9f078a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=550570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=551446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=552300"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/07");
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
if (rpm_check(release:"SL3", reference:"tzdata-2009u-1.el3")) flag++;

if (rpm_check(release:"SL4", reference:"tzdata-2009u-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"tzdata-2009u-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
