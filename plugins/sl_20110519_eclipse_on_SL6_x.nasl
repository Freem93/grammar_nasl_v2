#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61040);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2010-4647");

  script_name(english:"Scientific Linux Security Update : eclipse on SL6.x i386/x86_64");
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
"The Eclipse software development environment provides a set of tools
for C/C++ and Java development.

A cross-site scripting (XSS) flaw was found in the Eclipse Help
Contents web application. An attacker could use this flaw to perform a
cross-site scripting attack against victims by tricking them into
visiting a specially crafted Eclipse Help URL. (CVE-2010-4647)

The following Eclipse packages have been upgraded to the versions
found in the official upstream Eclipse Helios SR1 release, providing a
number of bug fixes and enhancements over the previous versions :

  - eclipse to 3.6.1.

  - eclipse-cdt to 7.0.1.

  - eclipse-birt to 2.6.0.

  - eclipse-emf to 2.6.0.

  - eclipse-gef to 3.6.1.

  - eclipse-mylyn to 3.4.2.

  - eclipse-rse to 3.2.

  - eclipse-dtp to 1.8.1.

  - eclipse-changelog to 2.7.0.

  - eclipse-valgrind to 0.6.1.

  - eclipse-callgraph to 0.6.1.

  - eclipse-oprofile to 0.6.1.

  - eclipse-linuxprofilingframework to 0.6.1.

In addition, the following updates were made to the dependencies of
the Eclipse packages above :

  - icu4j to 4.2.1.

  - sat4j to 2.2.0.

  - objectweb-asm to 3.2.

  - jetty-eclipse to 6.1.24.

This update includes numerous upstream bug fixes and enhancements,
such as :

  - The Eclipse IDE and Java Development Tools (JDT) :

    - projects and folders can filter out resources in the
      workspace.

    - new virtual folder and linked files support.

    - the full set of UNIX file permissions is now
      supported.

    - addition of the stop button to cancel long-running
      wizard tasks.

    - Java editor now shows multiple quick-fixes via problem
      hover.

    - new support for running JUnit version 4 tests.

    - over 200 upstream bug fixes.

  - The Eclipse C/C++ Development Tooling (CDT) :

    - new Codan framework has been added for static code
      analysis.

    - refactoring improvements such as stored refactoring
      history.

    - compile and build errors now highlighted in the build
      console.

    - switch to the new DSF debugger framework.

    - new template view support.

    - over 600 upstream bug fixes.

This update also fixes the following bugs :

  - Incorrect URIs for GNU Tools in the 'Help Contents'
    window have been fixed.

  - The profiling of binaries did not work if an Eclipse
    project was not in an Eclipse workspace. This update
    adds an automated test for external project profiling,
    which corrects this issue.

  - Running a C/C++ application in Eclipse successfully
    terminated, but returned an I/O exception not related to
    the application itself in the Error Log window. With
    this update, the exception is no longer returned.

  - The eclipse-mylyn package showed a '20100916-0100-e3x'
    qualifier. The qualifier has been modified to
    'v20100902-0100-e3x' to match the upstream version of
    eclipse-mylyn.

  - Installing the eclipse-mylyn package failed and returned
    a 'Resource temporarily unavailable' error message due
    to a bug in the packaging. This update fixes this bug
    and installation now works as expected.

  - Building the eclipse-cdt package could fail due to an
    incorrect interaction with the local file system.
    Interaction with the local file system is now prevented
    and the build no longer fails.

  - The libhover plug-in, provided by the eclipse-cdt
    package, used binary data to search for hover topics.
    The data location was specified externally as a URL
    which could cause an exception to occur on a system with
    no Internet access. This update modifies the plug-in so
    that it pulls the needed data from a local location.

Users of eclipse should upgrade to these updated packages, which
correct these issues and add these enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=2485
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdc2e8e0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"eclipse-birt-2.6.0-1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-callgraph-0.6.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-cdt-7.0.1-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-cdt-parsers-7.0.1-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-cdt-sdk-7.0.1-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-changelog-2.7.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-debuginfo-3.6.1-6.13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-dtp-1.8.1-1.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-emf-2.6.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-emf-examples-2.6.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-emf-sdk-2.6.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-emf-xsd-2.6.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-emf-xsd-sdk-2.6.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-gef-3.6.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-gef-examples-3.6.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-gef-sdk-3.6.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-jdt-3.6.1-6.13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-linuxprofilingframework-0.6.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-mylyn-3.4.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-mylyn-cdt-3.4.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-mylyn-java-3.4.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-mylyn-pde-3.4.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-mylyn-trac-3.4.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-mylyn-webtasks-3.4.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-mylyn-wikitext-3.4.2-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-oprofile-0.6.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-oprofile-debuginfo-0.6.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-pde-3.6.1-6.13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-platform-3.6.1-6.13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-rcp-3.6.1-6.13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-rse-3.2-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-swt-3.6.1-6.13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"eclipse-valgrind-0.6.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"icu4j-4.2.1-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"icu4j-eclipse-4.2.1-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"icu4j-javadoc-4.2.1-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"jetty-eclipse-6.1.24-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"objectweb-asm-3.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sat4j-2.2.0-4.0.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
