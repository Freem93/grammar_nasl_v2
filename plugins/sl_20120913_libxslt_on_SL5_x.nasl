#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62107);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/02/11 03:33:47 $");

  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871");

  script_name(english:"Scientific Linux Security Update : libxslt on SL5.x, SL6.x i386/x86_64");
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
"A heap-based buffer overflow flaw was found in the way libxslt applied
templates to nodes selected by certain namespaces. An attacker could
use this flaw to create a malicious XSL file that, when used by an
application linked against libxslt to perform an XSL transformation,
could cause the application to crash or, possibly, execute arbitrary
code with the privileges of the user running the application.
(CVE-2012-2871)

Several denial of service flaws were found in libxslt. An attacker
could use these flaws to create a malicious XSL file that, when used
by an application linked against libxslt to perform an XSL
transformation, could cause the application to crash. (CVE-2012-2825,
CVE-2012-2870, CVE-2011-3970)

An information leak could occur if an application using libxslt
processed an untrusted XPath expression, or used a malicious XSL file
to perform an XSL transformation. If combined with other flaws, this
leak could possibly help an attacker bypass intended memory corruption
protections. (CVE-2011-1202)

All running applications linked against libxslt must be restarted for
this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=2008
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1f6e6ba"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libxslt, libxslt-devel and / or libxslt-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libxslt-1.1.17-4.el5_8.3")) flag++;
if (rpm_check(release:"SL5", reference:"libxslt-devel-1.1.17-4.el5_8.3")) flag++;
if (rpm_check(release:"SL5", reference:"libxslt-python-1.1.17-4.el5_8.3")) flag++;

if (rpm_check(release:"SL6", reference:"libxslt-1.1.26-2.el6_3.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxslt-devel-1.1.26-2.el6_3.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxslt-python-1.1.26-2.el6_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
