#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60645);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2690");

  script_name(english:"Scientific Linux Security Update : java (jdk 1.6.0) on SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-0217 xmlsec1, mono, xml-security-c,
xml-security-1.3.0-1jpp.ep1.*: XMLDsig HMAC-based signatures spoofing
and authentication bypass

CVE-2009-2670 OpenJDK Untrusted applet System properties access
(6738524)

CVE-2009-2671 CVE-2009-2672 OpenJDK Proxy mechanism information leaks
(6801071)

CVE-2009-2673 OpenJDK proxy mechanism allows non-authorized socket
connections (6801497)

CVE-2009-2674 Java Web Start Buffer JPEG processing integer overflow
(6823373)

CVE-2009-2675 Java Web Start Buffer unpack200 processing integer
overflow (6830335)

CVE-2009-2625 OpenJDK XML parsing Denial-Of-Service (6845701)

CVE-2009-2475 OpenJDK information leaks in mutable variables
(6588003,6656586,6656610,6656625,6657133,6657619,6657625,6657695,66600
49,6660539,6813167)

CVE-2009-2476 OpenJDK OpenType checks can be bypassed (6736293)

CVE-2009-2690 OpenJDK private variable information disclosure
(6777487)

CVE-2009-2676 JRE applet launcher vulnerability

All running instances of Sun Java must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0908&L=scientific-linux-errata&T=0&P=2845
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42ba17de"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-sun-compat and / or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/24");
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
if (rpm_check(release:"SL4", reference:"java-1.6.0-sun-compat-1.6.0.16-1.sl4.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"jdk-1.6.0_16-fcs")) flag++;

if (rpm_check(release:"SL5", reference:"java-1.6.0-sun-compat-1.6.0.16-1.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.6.0_16-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
