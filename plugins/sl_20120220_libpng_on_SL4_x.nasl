#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61254);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-3026");

  script_name(english:"Scientific Linux Security Update : libpng on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A heap-based buffer overflow flaw was found in libpng. An attacker
could create a specially crafted PNG image that, when opened, could
cause an application using libpng to crash or, possibly, execute
arbitrary code with the privileges of the user running the
application. (CVE-2011-3026)

Users of libpng and libpng10 should upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications using libpng or libpng10 must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=3665
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8090800"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/20");
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
if (rpm_check(release:"SL4", reference:"libpng-1.2.7-9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpng-debuginfo-1.2.7-9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpng-devel-1.2.7-9.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpng10-1.0.16-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpng10-debuginfo-1.0.16-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpng10-devel-1.0.16-10.el4")) flag++;

if (rpm_check(release:"SL5", reference:"libpng-1.2.10-15.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"libpng-debuginfo-1.2.10-15.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"libpng-devel-1.2.10-15.el5_7")) flag++;

if (rpm_check(release:"SL6", reference:"libpng-1.2.46-2.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"libpng-debuginfo-1.2.46-2.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"libpng-devel-1.2.46-2.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"libpng-static-1.2.46-2.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");