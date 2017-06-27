#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60778);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_name(english:"Scientific Linux Security Update : tzdata on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"This updated package addresses the following change to Daylight Saving
Time (DST) observations :

  - although DST was previously announced as beginning in
    Pakistan on 2010-01-04, it has now been confirmed
    Pakistan will not observe any DST in 2010. (BZ#577710,
    BZ#577835, BZ#577837)

  - after observing DST as a trial in 2009, Bangladesh
    announced it will not observe DST in 2010. (Previous
    announcements had Bangladesh switching to DST on
    2010-04-01. This will now not happen.) (BZ#576268,
    BZ#576613, BZ#576614)

  - Tunisia did not observer DST in 2009, remaining on
    UTC+1. On 2010-02-27, it was announced Tunisia would
    also not observe DST in 2010. (BZ#577793, BZ#577841,
    BZ#577842)

  - On 2010-03-28, the number of time zones used in Russia
    was reduced from eleven to nine. Two regions -- the
    Samara Oblast and the Udmurt Republic -- were switched
    from UTC+4 to UTC+3. Two others regions -- the Kamchatka
    Krai and the Chukotka Autonomous Okrug -- were switched
    to UTC+11. (BZ#576268, BZ#576613, BZ#576614)

  - On 2010-03-17, it was announced Syria would move to DST
    on 2010-04-02 at 00:00. This is one week later than the
    previously gazetted date of 2010-03-26. (No BZ#)

  - DST transition dates and times for several Australian
    Antarctic Stations were changed. Casey station switched
    back to UTC+8 on 2010-03-10; Davis Station switched back
    to UTC+7 on 2010-03-10. Macquarie Island station will
    remain at UTC+11 and will not switch back to UTC+10 when
    Tasmania ends its DST observance on 2010-04-04, as was
    previously gazetted. (No BZ#)

  - as announced on 25th March 2010, DST in the Gaza Strip
    will start on 2010-03-27 at 00:01. This is 24-hours
    after DST begins in the West Bank and Israel. (No BZ#)

  - Samoa's DST transition date was corrected. (No BZ#)

Additionally, on Scientific Linux 5, this update brings timezone data
for Java Runtime Environment, in the included subpackage tzdata-java.
(BZ#576611)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=196
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c6b3ad7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=576268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=576611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=576613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=576614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=577710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=577793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=577835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=577837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=577841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=577842"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata and / or tzdata-java packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
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
if (rpm_check(release:"SL3", reference:"tzdata-2010f-3.el3")) flag++;

if (rpm_check(release:"SL4", reference:"tzdata-2010f-3.el4")) flag++;

if (rpm_check(release:"SL5", reference:"tzdata-2010f-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tzdata-java-2010f-10.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
