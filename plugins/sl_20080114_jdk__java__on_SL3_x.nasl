#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60344);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-3503", "CVE-2007-3655", "CVE-2007-3698", "CVE-2007-3922", "CVE-2007-5232", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274");

  script_name(english:"Scientific Linux Security Update : jdk (java) on SL3.x, SL4.x i386/x86_64");
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
"NOTE: This combination of rpm's replaces j2sdk-1.4.2 with jdk-1.5.0.
So your java will change from version 1.4.2 to 1.5.0. We apologize if
this causes any problems, but it needed to be done for security
reasons.

A flaw in the applet caching mechanism of the Java Runtime Environment
(JRE) did not correctly process the creation of network connections. A
remote attacker could use this flaw to create connections to services
on machines other than the one that the applet was downloaded from.
(CVE-2007-5232)

Multiple vulnerabilities existed in Java Web Start allowing an
untrusted application to determine the location of the Java Web Start
cache. (CVE-2007-5238)

Untrusted Java Web Start Applications or Java Applets were able to
drag and drop a file to a Desktop Application. A user-assisted remote
attacker could use this flaw to move or copy arbitrary files.
(CVE-2007-5239)

The Java Runtime Environment (JRE) allowed untrusted Java Applets or
applications to display oversized Windows. This could be used by
remote attackers to hide security warning banners. (CVE-2007-5240)

Unsigned Java Applets communicating via a HTTP proxy could allow a
remote attacker to violate the Java security model. A cached,
malicious Applet could create network connections to services on other
machines. (CVE-2007-5273)

Unsigned Applets loaded with Mozilla Firefox or Opera browsers allowed
remote attackers to violate the Java security model. A cached,
malicious Applet could create network connections to services on other
machines. (CVE-2007-5274) The Javadoc tool was able to generate HTML
documentation pages that contained cross-site scripting (XSS)
vulnerabilities. A remote attacker could use this to inject arbitrary
web script or HTML. (CVE-2007-3503)

The Java Web Start URL parsing component contained a buffer overflow
vulnerability within the parsing code for JNLP files. A remote
attacker could create a malicious JNLP file that could trigger this
flaw and execute arbitrary code when opened. (CVE-2007-3655)

The JSSE component did not correctly process SSL/TLS handshake
requests. A remote attacker who is able to connect to a JSSE-based
service could trigger this flaw leading to a denial-of-service.
(CVE-2007-3698)

A flaw was found in the applet class loader. An untrusted applet could
use this flaw to circumvent network access restrictions, possibly
connecting to services hosted on the machine that executed the applet.
(CVE-2007-3922)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0801&L=scientific-linux-errata&T=0&P=852
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76b60cd9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected java-1.4.2-sun-compat, java-1.5.0-sun-compat and /
or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/14");
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
if (rpm_check(release:"SL3", reference:"java-1.4.2-sun-compat-1.4.2.90-1jpp")) flag++;
if (rpm_check(release:"SL3", reference:"java-1.5.0-sun-compat-1.5.0.14-1.sl.jpp")) flag++;
if (rpm_check(release:"SL3", reference:"jdk-1.5.0_14-fcs")) flag++;

if (rpm_check(release:"SL4", reference:"java-1.4.2-sun-compat-1.4.2.90-1jpp")) flag++;
if (rpm_check(release:"SL4", reference:"java-1.5.0-sun-compat-1.5.0.14-1.sl4.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"jdk-1.5.0_14-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
