#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65654);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/22 10:44:21 $");

  script_cve_id("CVE-2013-0254");

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
"It was discovered that the QSharedMemory class implementation of the
Qt toolkit created shared memory segments with insecure permissions. A
local attacker could use this flaw to read or alter the contents of a
particular shared memory segment, possibly leading to their ability to
obtain sensitive information or influence the behavior of a process
that is using the shared memory segment. (CVE-2013-0254)

All running applications linked against Qt libraries must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=5398
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a0593a4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"phonon-backend-gstreamer-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-debuginfo-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-demos-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-devel-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-doc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-examples-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-mysql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-odbc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-postgresql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-sqlite-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"qt-x11-4.6.2-26.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
