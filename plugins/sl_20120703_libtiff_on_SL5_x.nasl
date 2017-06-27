#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(83916);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/01 14:14:15 $");

  script_cve_id("CVE-2012-2088", "CVE-2012-2113");

  script_name(english:"Scientific Linux Security Update : libtiff on SL5.x, SL6.x i386/x86_64");
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
"The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

libtiff did not properly convert between signed and unsigned integer
values, leading to a buffer overflow. An attacker could use this flaw
to create a specially crafted TIFF file that, when opened, would cause
an application linked against libtiff to crash or, possibly, execute
arbitrary code. (CVE-2012-2088)

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the tiff2pdf tool. An attacker could use
these flaws to create a specially crafted TIFF file that would cause
tiff2pdf to crash or, possibly, execute arbitrary code.
(CVE-2012-2113)

All libtiff users should upgrade to these updated packages, which
contain backported patches to resolve these issues. All running
applications linked against libtiff must be restarted for this update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=1120
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31f2d87e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libtiff-3.8.2-15.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"libtiff-debuginfo-3.8.2-15.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"libtiff-devel-3.8.2-15.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"libtiff-3.9.4-6.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-debuginfo-3.9.4-6.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-devel-3.9.4-6.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-static-3.9.4-6.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
