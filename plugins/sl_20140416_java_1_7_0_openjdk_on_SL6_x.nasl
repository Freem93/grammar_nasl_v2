#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73590);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/28 19:00:57 $");

  script_cve_id("CVE-2013-5797", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL6.x i386/x86_64");
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
"An input validation flaw was discovered in the medialib library in the
2D component. A specially crafted image could trigger Java Virtual
Machine memory corruption when processed. A remote attacker, or an
untrusted Java application or applet, could possibly use this flaw to
execute arbitrary code with the privileges of the user running the
Java Virtual Machine. (CVE-2014-0429)

Multiple flaws were discovered in the Hotspot and 2D components in
OpenJDK. An untrusted Java application or applet could use these flaws
to trigger Java Virtual Machine memory corruption and possibly bypass
Java sandbox restrictions. (CVE-2014-0456, CVE-2014-2397,
CVE-2014-2421)

Multiple improper permission check issues were discovered in the
Libraries component in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2014-0457, CVE-2014-0455, CVE-2014-0461)

Multiple improper permission check issues were discovered in the AWT,
JAX- WS, JAXB, Libraries, Security, Sound, and 2D components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2014-2412,
CVE-2014-0451, CVE-2014-0458, CVE-2014-2423, CVE-2014-0452,
CVE-2014-2414, CVE-2014-2402, CVE-2014-0446, CVE-2014-2413,
CVE-2014-0454, CVE-2014-2427, CVE-2014-0459)

Multiple flaws were identified in the Java Naming and Directory
Interface (JNDI) DNS client. These flaws could make it easier for a
remote attacker to perform DNS spoofing attacks. (CVE-2014-0460)

It was discovered that the JAXP component did not properly prevent
access to arbitrary files when a SecurityManager was present. This
flaw could cause a Java application using JAXP to leak sensitive
information, or affect application availability. (CVE-2014-2403)

It was discovered that the Security component in OpenJDK could leak
some timing information when performing PKCS#1 unpadding. This could
possibly lead to the disclosure of some information that was meant to
be protected by encryption. (CVE-2014-0453)

It was discovered that the fix for CVE-2013-5797 did not properly
resolve input sanitization flaws in javadoc. When javadoc
documentation was generated from an untrusted Java source code and
hosted on a domain not controlled by the code author, these issues
could make it easier to perform cross-site scripting (XSS) attacks.
(CVE-2014-2398)

An insecure temporary file use flaw was found in the way the unpack200
utility created log files. A local attacker could possibly use this
flaw to perform a symbolic link attack and overwrite arbitrary files
with the privileges of the user running unpack200. (CVE-2014-1876)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1404&L=scientific-linux-errata&T=0&P=1440
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a95f4d0a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-1.7.0.55-2.4.7.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.55-2.4.7.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-demo-1.7.0.55-2.4.7.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-devel-1.7.0.55-2.4.7.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.55-2.4.7.1.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-src-1.7.0.55-2.4.7.1.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
