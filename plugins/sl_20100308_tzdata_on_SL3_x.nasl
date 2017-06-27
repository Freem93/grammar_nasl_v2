#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60744);
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
"This update addresses several changes in Daylight Savings Time (DST)
observation including the following :

  - on February 17th 2010, it was announced that Paraguay
    would extend its 2010 DST observance to Sunday, 11th
    April 2010. (It had been scheduled to end on Sunday,
    14th March 2010.) The same announcement also noted the
    2010-2011 DST observance would begin on Sunday, 3d
    October 2010 (the 1st Sunday in October, rather than the
    previously scheduled 3rd Sunday, 17th October 2010).
    (BZ#568665, BZ#568666, BZ#568667)

  - several cities and towns bordering the United States in
    Northern Mexico will synchronize their DST schedules
    with their Northern neighbor beginning this year. Places
    affected by this change include Tijuana; Mexicali;
    Ciudad Juarez; Ojinaga; Ciudad Acuna; Piedras Negras;
    Anahuac; Nuevo Laredo; Reynosa; and Matamoros. Each of
    these locales will switch to DST on Sunday, 14th March
    2010 and switch back on Sunday, 7th November 2010. This
    is in line with the US DST schedule, which runs from the
    second Sunday of March to the first Sunday of November.
    (No BZ#)

Note: the rest of Mexico will continue to observe DST (or not observe
DST in the case of Sonora, which remains on Mountain Standard Time all
year) from the 2nd Sunday in April through the last Sunday in October."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=753
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d4c1fd3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=568665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=568666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=568667"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/08");
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
if (rpm_check(release:"SL3", reference:"tzdata-2010c-1.el3")) flag++;

if (rpm_check(release:"SL4", reference:"tzdata-2010c-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"tzdata-2010c-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
