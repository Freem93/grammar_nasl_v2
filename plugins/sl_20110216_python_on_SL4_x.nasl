#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60960);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450");

  script_name(english:"Scientific Linux Security Update : python on SL4.x i386/x86_64");
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
"Multiple flaws were found in the Python rgbimg module. If an
application written in Python was using the rgbimg module and loaded a
specially crafted SGI image file, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2009-4134, CVE-2010-1449,
CVE-2010-1450)

This update also fixes the following bugs :

  - Python 2.3.4's time.strptime() function did not
    correctly handle the '%W' week number format string.
    This update backports the _strptime implementation from
    Python 2.3.6, fixing this issue. (BZ#436001)

  - Python 2.3.4's socket.htons() function returned
    partially-uninitialized data on IBM System z, generally
    leading to incorrect results. (BZ#513341)

  - Python 2.3.4's pwd.getpwuid() and grp.getgrgid()
    functions did not support the full range of user and
    group IDs on 64-bit architectures, leading to
    'OverflowError' exceptions for large input values. This
    update adds support for the full range of user and group
    IDs on 64-bit architectures. (BZ#497540)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=1967
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97b64b12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=436001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=513341"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (rpm_check(release:"SL4", reference:"python-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"python-devel-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"python-docs-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"python-tools-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"tkinter-2.3.4-14.9.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
