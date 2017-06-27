#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63071);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/11/28 12:18:54 $");

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

  - On October 24 2012, the Jordanian Cabinet rescinded a
    2012-10-14 instruction to switch from daylight saving
    time (DST) to standard time on 2012-10-26. Instead,
    Jordan will remain on local DST (ITC +3) for the
    2012-2013 Jordanian winter.

  - Cuba, which was scheduled to move back to standard time
    on 2012-11-12, switched to standard time on 2012-11-04.

  - In Brazil, the North Region state, Tocantins, will
    observe DST in 2012-2013. This is the first time
    Tocantins has observed DST since 2003. By contrast,
    Bahia, a Northeast Region state, will not observe DST in
    2012-2013. Like Tocantins, Bahia stopped observing DST
    in 2003. Bahia re-introduced DST on October 16 2011. On
    October 17 2012, however, Bahia Governor, Jaques Wagner,
    announced DST would not be observed in 2012, citing
    public surveys showing most Bahia residents were opposed
    to it.

  - Israel has new DST rules as of 2013. DST now starts at
    02:00 on the Friday before the last Sunday in March. DST
    now ends at 02:00 on the first Sunday after October 1,
    unless this day is also the second day of (Rosh
    Hashanah). In this case, DST ends a day later, at 02:00
    on the first Monday after October 2.

  - The Palestinian territories, which were scheduled to
    move back to standard time on 2012-09-28, switched to
    standard time on 2012-09-21.

  - Although Western Samoa has observed DST for two
    consecutive seasons (2010-2011 and 2011-2012), there is
    no official indication of DST continuing according to a
    set pattern for the foreseeable future. On 2012-09-04,
    the Samoan Ministry of Commerce, Industry, and Labour
    announced Samoa would observe DST from Sunday,
    2012-09-30 until Sunday 2012-04-07.

This update has been placed in the security tree to avoid timezone
related problems such as ntp sync errors."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1211&L=scientific-linux-errata&T=0&P=2357
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4adcaba4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata and / or tzdata-java packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");
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
if (rpm_check(release:"SL5", reference:"tzdata-2012i-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tzdata-java-2012i-2.el5")) flag++;

if (rpm_check(release:"SL6", reference:"tzdata-2012i-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"tzdata-java-2012i-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
