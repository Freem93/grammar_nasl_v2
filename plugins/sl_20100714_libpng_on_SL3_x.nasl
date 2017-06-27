#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60816);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2042", "CVE-2010-0205", "CVE-2010-1205", "CVE-2010-2249");

  script_name(english:"Scientific Linux Security Update : libpng on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A memory corruption flaw was found in the way applications, using the
libpng library and its progressive reading method, decoded certain PNG
images. An attacker could create a specially crafted PNG image that,
when opened, could cause an application using libpng to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-1205)

A denial of service flaw was found in the way applications using the
libpng library decoded PNG images that have certain, highly compressed
ancillary chunks. An attacker could create a specially crafted PNG
image that could cause an application using libpng to consume
excessive amounts of memory and CPU time, and possibly crash.
(CVE-2010-0205)

A memory leak flaw was found in the way applications using the libpng
library decoded PNG images that use the Physical Scale (sCAL)
extension. An attacker could create a specially crafted PNG image that
could cause an application using libpng to exhaust all available
memory and possibly crash or exit. (CVE-2010-2249)

A sensitive information disclosure flaw was found in the way
applications using the libpng library processed 1-bit interlaced PNG
images. An attacker could create a specially crafted PNG image that
could cause an application using libpng to disclose uninitialized
memory. (CVE-2009-2042)

All running applications using libpng or libpng10 must be restarted
for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=1396
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?275df5ff"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"libpng-1.2.2-30")) flag++;
if (rpm_check(release:"SL3", reference:"libpng-devel-1.2.2-30")) flag++;
if (rpm_check(release:"SL3", reference:"libpng10-1.0.13-21")) flag++;
if (rpm_check(release:"SL3", reference:"libpng10-devel-1.0.13-21")) flag++;

if (rpm_check(release:"SL4", reference:"libpng-1.2.7-3.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"libpng-devel-1.2.7-3.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"libpng10-1.0.16-3.el4_8.4")) flag++;
if (rpm_check(release:"SL4", reference:"libpng10-devel-1.0.16-3.el4_8.4")) flag++;

if (rpm_check(release:"SL5", reference:"libpng-1.2.10-7.1.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"libpng-devel-1.2.10-7.1.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
