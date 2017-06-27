#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61140);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2007-0242", "CVE-2011-3193");

  script_name(english:"Scientific Linux Security Update : qt4 on SL5.x i386/x86_64");
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
"Qt 4 is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System. HarfBuzz is an OpenType text shaping engine.

A flaw in the way Qt 4 expanded certain UTF-8 characters could be used
to prevent a Qt 4 based application from properly sanitizing user
input. Depending on the application, this could allow an attacker to
perform directory traversal, or for web applications, a cross-site
scripting (XSS) attack. (CVE-2007-0242)

A buffer overflow flaw was found in the harfbuzz module in Qt 4. If a
user loaded a specially crafted font file with an application linked
against Qt 4, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3193)

Users of Qt 4 should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
linked against Qt 4 libraries must be restarted for this update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=2708
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cf0d57f"
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
if (rpm_check(release:"SL5", reference:"qt4-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"qt4-debuginfo-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"qt4-devel-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"qt4-doc-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"qt4-mysql-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"qt4-odbc-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"qt4-postgresql-4.2.1-1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"qt4-sqlite-4.2.1-1.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
