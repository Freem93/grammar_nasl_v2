#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60633);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL5.3 i386/x86_64");
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

CVE-2009-2689 OpenJDK JDK13Services grants unnecessary privileges
(6777448)

CVE-2009-2690 OpenJDK private variable information disclosure
(6777487)

A flaw was found in the way the XML Digital Signature implementation
in the JRE handled HMAC-based XML signatures. An attacker could use
this flaw to create a crafted signature that could allow them to
bypass authentication, or trick a user, applet, or application into
accepting untrusted content. (CVE-2009-0217)

Several potential information leaks were found in various mutable
static variables. These could be exploited in application scenarios
that execute untrusted scripting code. (CVE-2009-2475)

It was discovered that OpenType checks can be bypassed. This could
allow a rogue application to bypass access restrictions by acquiring
references to privileged objects through finalizer resurrection.
(CVE-2009-2476)

A denial of service flaw was found in the way the JRE processes XML. A
remote attacker could use this flaw to supply crafted XML that would
lead to a denial of service. (CVE-2009-2625)

A flaw was found in the JRE audio system. An untrusted applet or
application could use this flaw to gain read access to restricted
System properties. (CVE-2009-2670)

Two flaws were found in the JRE proxy implementation. An untrusted
applet or application could use these flaws to discover the usernames
of users running applets and applications, or obtain web browser
cookies and use them for session hijacking attacks. (CVE-2009-2671,
CVE-2009-2672)

An additional flaw was found in the proxy mechanism implementation.
This flaw allowed an untrusted applet or application to bypass access
restrictions and communicate using non-authorized socket or URL
connections to hosts other than the origin host. (CVE-2009-2673)

An integer overflow flaw was found in the way the JRE processes JPEG
images. An untrusted application could use this flaw to extend its
privileges, allowing it to read and write local files, as well as to
execute local applications with the privileges of the user running the
application. (CVE-2009-2674)

An integer overflow flaw was found in the JRE unpack200 functionality.
An untrusted applet or application could extend its privileges,
allowing it to read and write local files, as well as to execute local
applications with the privileges of the user running the applet or
application. (CVE-2009-2675)

It was discovered that JDK13Services grants unnecessary privileges to
certain object types. This could be misused by an untrusted applet or
application to use otherwise restricted functionality. (CVE-2009-2689)

An information disclosure flaw was found in the way private Java
variables were handled. An untrusted applet or application could use
this flaw to obtain information from variables that would otherwise be
private. (CVE-2009-2690)

Note: The flaws concerning applets in this advisory, CVE-2009-2475,

CVE-2009-2670, CVE-2009-2671, CVE-2009-2672, CVE-2009-2673,

CVE-2009-2675, CVE-2009-2689, and CVE-2009-2690, can only be triggered
in java-1.6.0-openjdk by calling the 'appletviewer' application.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0908&L=scientific-linux-errata&T=0&P=2708
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0305b4c3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
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
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.2.b09.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.2.b09.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
