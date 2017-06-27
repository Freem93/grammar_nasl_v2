#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99622);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/05 13:31:48 $");

  script_cve_id("CVE-2016-5542", "CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL7.x x86_64");
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
"Security Fix(es) :

  - An untrusted library search path flaw was found in the
    JCE component of OpenJDK. A local attacker could
    possibly use this flaw to cause a Java application using
    JCE to load an attacker-controlled library and hence
    escalate their privileges. (CVE-2017-3511)

  - It was found that the JAXP component of OpenJDK failed
    to correctly enforce parse tree size limits when parsing
    XML document. An attacker able to make a Java
    application parse a specially crafted XML document could
    use this flaw to make it consume an excessive amount of
    CPU and memory. (CVE-2017-3526)

  - It was discovered that the HTTP client implementation in
    the Networking component of OpenJDK could cache and
    re-use an NTLM authenticated connection in a different
    security context. A remote attacker could possibly use
    this flaw to make a Java application perform HTTP
    requests authenticated with credentials of a different
    user. (CVE-2017-3509)

Note: This update adds support for the 'jdk.ntlm.cache' system
property which, when set to false, prevents caching of NTLM
connections and authentications and hence prevents this issue.
However, caching remains enabled by default.

  - It was discovered that the Security component of OpenJDK
    did not allow users to restrict the set of algorithms
    allowed for Jar integrity verification. This flaw could
    allow an attacker to modify content of the Jar file that
    used weak signing key or hash algorithm. (CVE-2017-3539)

Note: This updates extends the fix for CVE-2016-5542 released as part
of the SLSA-2016:2079 erratum to no longer allow the MD5 hash
algorithm during the Jar integrity verification by adding it to the
jdk.jar.disabledAlgorithms security property.

  - Newline injection flaws were discovered in FTP and SMTP
    client implementations in the Networking component in
    OpenJDK. A remote attacker could possibly use these
    flaws to manipulate FTP or SMTP connections established
    by a Java application. (CVE-2017-3533, CVE-2017-3544)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

Bug Fix(es) :

  - When a method is called using the Java Debug Wire
    Protocol (JDWP) 'invokeMethod' command in a target Java
    virtual machine, JDWP creates global references for
    every Object that is implied in the method invocation,
    as well as for the returned argument of the reference
    type. Previously, the global references created for such
    arguments were not collected (deallocated) by the
    garbage collector after 'invokeMethod' finished. This
    consequently caused memory leaks, and because references
    to such objects were never released, the debugged
    application could be terminated with an Out of Memory
    error. This bug has been fixed, and the described
    problem no longer occurs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=20207
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f5fe297"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.131-2.b11.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.131-2.b11.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
