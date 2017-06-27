#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60367);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2006-4484", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3475", "CVE-2007-3476");

  script_name(english:"Scientific Linux Security Update : gd on SL4.x, SL5.x i386/x86_64");
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
"Multiple issues were discovered in the gd GIF image-handling code. A
carefully-crafted GIF file could cause a crash or possibly execute
code with the privileges of the application using the gd library.
(CVE-2006-4484, CVE-2007-3475, CVE-2007-3476)

An integer overflow was discovered in the gdImageCreateTrueColor()
function, leading to incorrect memory allocations. A carefully crafted
image could cause a crash or possibly execute code with the privileges
of the application using the gd library. (CVE-2007-3472)

A buffer over-read flaw was discovered. This could cause a crash in an
application using the gd library to render certain strings using a
JIS-encoded font. (CVE-2007-0455)

A flaw was discovered in the gd PNG image handling code. A truncated
PNG image could cause an infinite loop in an application using the gd
library. (CVE-2007-2756)

A flaw was discovered in the gd X BitMap (XBM) image-handling code. A
malformed or truncated XBM image could cause a crash in an application
using the gd library. (CVE-2007-3473)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0802&L=scientific-linux-errata&T=0&P=1905
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43036bcd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gd, gd-devel and / or gd-progs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/28");
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
if (rpm_check(release:"SL4", reference:"gd-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"gd-devel-2.0.28-5.4E.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"gd-progs-2.0.28-5.4E.el4_6.1")) flag++;

if (rpm_check(release:"SL5", reference:"gd-2.0.33-9.4.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"gd-devel-2.0.33-9.4.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"gd-progs-2.0.33-9.4.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
