#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60277);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_name(english:"Scientific Linux Security Update : tzdata on SL3.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A tzdata enhancement, with updates for Venezuela, Indiana, Egypt,
Gaza, South Australia, Antarctica, Brazil, and Iran is now available.

The tzdata package contains data files with information regarding and
rules for daylight saving times in various timezones around the world.

The updated package contains up to date rules for the following
timezones :

  - Daviess, Dubois, Knox, Martin, and Pike Counties,
    Indiana, switch from Central Standard Time(CST) to
    Eastern Standard Time(EST) in November.

  - South Australia, Tasmania, Victoria, and New South Wales
    are changing the Daylight Savings Time rules for next
    year.

  - Several Antarctic stations rules were not properly
    updated to account for this year's change to the New
    Zealand daylight saving rules.

  - Brazil will observe Daylight Savings Time from October
    14 2007 to February 17 2008.

  - Egypt and Gaza switched to Daylight Savings Time on
    September 7 not September 24.

  - Iran resumes Daylight Savings Time next year.

  - Venezuela is scheduled to change time zone to -4:30 on
    January 1."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0710&L=scientific-linux-errata&T=0&P=2315
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9480ea85"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tzdata package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/26");
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
if (rpm_check(release:"SL3", reference:"tzdata-2007h-1.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
