#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60501);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_name(english:"Scientific Linux Security Update : java (jdk 1.6.0) on SL4.x, SL5.x i386/x86_64");
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
"The jdk in Scientific Linux 4 and 5 is being updated from 1.5.0 to
1.6.0. This update provides some security updates, as well as several
feature updates. Java code that was able to run on version 1.5.0
should be able run on the 1.6.0 version. It is recommended that you
recompiled your java code on 1.6.0, but it is not required.

NOTE1: jdk-1.6.0_10-fcs.i586.rpm has been digitally signed, but
jdk-1.6.0_10-fcs.x86_64.rpm has not been. We tried out best, but were
not able to sign it without breaking it."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0812&L=scientific-linux-errata&T=0&P=193
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48472607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected java-1.5.0-sun-compat, java-1.6.0-sun-compat and /
or jdk packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/02");
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
if (rpm_check(release:"SL4", reference:"java-1.5.0-sun-compat-1.5.0.90-2.sl.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"java-1.6.0-sun-compat-1.6.0.10-3.sl4.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"jdk-1.6.0_10-fcs")) flag++;

if (rpm_check(release:"SL5", reference:"java-1.5.0-sun-compat-1.5.0.90-2.sl.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-sun-compat-1.6.0.10-3.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.6.0_10-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
