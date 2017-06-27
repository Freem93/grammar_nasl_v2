#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61289);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_name(english:"Scientific Linux Security Update : tzdata on SL5.x, SL6.x i386/x86_64");
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
"This updated package adds the following time-zone changes to the zone
info database :

  - On 2012-03-15, Morocco announced it will switch to
    daylight savings time (DST) on the last Sunday in April
    (29th April) and not the 25th of March. The earlier date
    was announced as the daylight savings switch date on
    2012-03-09. The change was made 'after discussion of
    proposals to consider the demands of schooling',
    according to Mustapha El Khalfi, the Morocco Minister of
    Communications. The switch back to standard Moroccan
    time will still occur at 03:00 on the last Sunday in
    September, 2012-09-30. This update reflects the later
    switching date announced on 2012-03-15.

  - Armenia announced it will abolish local daylight savings
    time observance. This update reflects this: the Armenian
    time-zone will not advance an hour on 2012-03-24 as was
    previously set.

  - The Falkland Islands announced it will remain on
    Falklands Summer Time for the rest of 2012 and will
    likely remain so for future years. This update assumes a
    permanent summer time for the Falkland Islands until
    advised differently.

  - Cuba has delayed the 2012 DST switch by three weeks.
    Originally set to switch at 01:00 2012-03-11, Cuba will
    now switch to local DST at 01:00 2012-04-01. The switch
    back to standard time remains unchanged at 2012-11-13.
    This update incorporates the delayed DST switch for
    Cuba."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=4309
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0cb26ba"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata and / or tzdata-java packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/23");
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
if (rpm_check(release:"SL5", reference:"tzdata-2012b-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tzdata-java-2012b-3.el5")) flag++;

if (rpm_check(release:"SL6", reference:"tzdata-2012b-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tzdata-java-2012b-3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
