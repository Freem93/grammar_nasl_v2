#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61141);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-3193", "CVE-2011-3194");

  script_name(english:"Scientific Linux Security Update : qt on SL6.x i386/x86_64");
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
"Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System. HarfBuzz is an OpenType text shaping engine.

A buffer overflow flaw was found in the harfbuzz module in Qt. If a
user loaded a specially crafted font file with an application linked
against Qt, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3193)

A buffer overflow flaw was found in the way Qt handled certain
gray-scale image files. If a user loaded a specially crafted
gray-scale image file with an application linked against Qt, it could
cause the application to crash or, possibly, execute arbitrary code
with the privileges of the user running the application.
(CVE-2011-3194)

Users of Qt should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
linked against Qt libraries must be restarted for this update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=2956
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f45f2cad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"phonon-backend-gstreamer-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-debuginfo-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-demos-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-devel-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-doc-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-examples-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-mysql-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-odbc-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-postgresql-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-sqlite-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"qt-x11-4.6.2-17.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
