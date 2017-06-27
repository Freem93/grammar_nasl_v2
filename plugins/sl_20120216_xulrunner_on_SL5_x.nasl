#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61253);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2011-3026");

  script_name(english:"Scientific Linux Security Update : xulrunner on SL5.x, SL6.x i386/x86_64");
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
"XULRunner provides the XUL Runtime environment for applications using
the Gecko layout engine.

A heap-based buffer overflow flaw was found in the way XULRunner
handled PNG (Portable Network Graphics) images. A web page containing
a malicious PNG image could cause an application linked against
XULRunner (such as Firefox) to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2011-3026)

All XULRunner users should upgrade to these updated packages, which
correct this issue. After installing the update, applications using
XULRunner must be restarted for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=3309
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fa80507"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected xulrunner, xulrunner-debuginfo and / or
xulrunner-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
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
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.26-2.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-1.9.2.26-2.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.26-2.el5_7")) flag++;

if (rpm_check(release:"SL6", reference:"xulrunner-1.9.2.26-2.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-1.9.2.26-2.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-1.9.2.26-2.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
