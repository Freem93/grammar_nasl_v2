#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0568. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54595);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2010-4647");
  script_bugtraq_id(44883);
  script_osvdb_id(69266, 69267);
  script_xref(name:"RHSA", value:"2011:0568");

  script_name(english:"RHEL 6 : eclipse (RHSA-2011:0568)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated eclipse packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Eclipse software development environment provides a set of tools
for C/C++ and Java development.

A cross-site scripting (XSS) flaw was found in the Eclipse Help
Contents web application. An attacker could use this flaw to perform a
cross-site scripting attack against victims by tricking them into
visiting a specially crafted Eclipse Help URL. (CVE-2010-4647)

The following Eclipse packages have been upgraded to the versions
found in the official upstream Eclipse Helios SR1 release, providing a
number of bug fixes and enhancements over the previous versions :

* eclipse to 3.6.1. (BZ#656329) * eclipse-cdt to 7.0.1. (BZ#656333) *
eclipse-birt to 2.6.0. (BZ#656391) * eclipse-emf to 2.6.0. (BZ#656344)
* eclipse-gef to 3.6.1. (BZ#656347) * eclipse-mylyn to 3.4.2.
(BZ#656337) * eclipse-rse to 3.2. (BZ#656338) * eclipse-dtp to 1.8.1.
(BZ#656397) * eclipse-changelog to 2.7.0. (BZ#669499) *
eclipse-valgrind to 0.6.1. (BZ#669460) * eclipse-callgraph to 0.6.1.
(BZ#669462) * eclipse-oprofile to 0.6.1. (BZ#670228) *
eclipse-linuxprofilingframework to 0.6.1. (BZ#669461)

In addition, the following updates were made to the dependencies of
the Eclipse packages above :

* icu4j to 4.2.1. (BZ#656342) * sat4j to 2.2.0. (BZ#661842) *
objectweb-asm to 3.2. (BZ#664019) * jetty-eclipse to 6.1.24.
(BZ#661845)

This update includes numerous upstream bug fixes and enhancements,
such as :

* The Eclipse IDE and Java Development Tools (JDT) :

  - projects and folders can filter out resources in the
    workspace. - new virtual folder and linked files
    support. - the full set of UNIX file permissions is now
    supported. - addition of the stop button to cancel
    long-running wizard tasks. - Java editor now shows
    multiple quick-fixes via problem hover. - new support
    for running JUnit version 4 tests. - over 200 upstream
    bug fixes.

* The Eclipse C/C++ Development Tooling (CDT) :

  - new Codan framework has been added for static code
    analysis. - refactoring improvements such as stored
    refactoring history. - compile and build errors now
    highlighted in the build console. - switch to the new
    DSF debugger framework. - new template view support. -
    over 600 upstream bug fixes.

This update also fixes the following bugs :

* Incorrect URIs for GNU Tools in the 'Help Contents' window have been
fixed. (BZ#622713)

* The profiling of binaries did not work if an Eclipse project was not
in an Eclipse workspace. This update adds an automated test for
external project profiling, which corrects this issue. (BZ#622867)

* Running a C/C++ application in Eclipse successfully terminated, but
returned an I/O exception not related to the application itself in the
Error Log window. With this update, the exception is no longer
returned. (BZ#668890)

* The eclipse-mylyn package showed a '20100916-0100-e3x' qualifier.
The qualifier has been modified to 'v20100902-0100-e3x' to match the
upstream version of eclipse-mylyn. (BZ#669819)

* Installing the eclipse-mylyn package failed and returned a 'Resource
temporarily unavailable' error message due to a bug in the packaging.
This update fixes this bug and installation now works as expected.
(BZ#673174)

* Building the eclipse-cdt package could fail due to an incorrect
interaction with the local file system. Interaction with the local
file system is now prevented and the build no longer fails.
(BZ#678364)

* The libhover plug-in, provided by the eclipse-cdt package, used
binary data to search for hover topics. The data location was
specified externally as a URL which could cause an exception to occur
on a system with no Internet access. This update modifies the plug-in
so that it pulls the needed data from a local location. (BZ#679543)

Users of eclipse should upgrade to these updated packages, which
correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0568.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-birt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-callgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-cdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-cdt-parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-cdt-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-changelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-dtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-emf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-emf-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-emf-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-emf-xsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-emf-xsd-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-gef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-gef-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-gef-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-jdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-linuxprofilingframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-mylyn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-mylyn-cdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-mylyn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-mylyn-pde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-mylyn-trac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-mylyn-webtasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-mylyn-wikitext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-oprofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-oprofile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-pde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-rcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-rse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-swt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eclipse-valgrind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:icu4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:icu4j-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:icu4j-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jetty-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sat4j");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0568";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-birt-2.6.0-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-birt-2.6.0-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-callgraph-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-callgraph-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-cdt-7.0.1-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-cdt-7.0.1-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-cdt-parsers-7.0.1-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-cdt-parsers-7.0.1-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-cdt-sdk-7.0.1-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-cdt-sdk-7.0.1-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-changelog-2.7.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-changelog-2.7.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-debuginfo-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-debuginfo-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-dtp-1.8.1-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-dtp-1.8.1-1.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-emf-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-emf-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-emf-examples-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-emf-examples-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-emf-sdk-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-emf-sdk-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-emf-xsd-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-emf-xsd-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-emf-xsd-sdk-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-emf-xsd-sdk-2.6.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-gef-3.6.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-gef-3.6.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-gef-examples-3.6.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-gef-examples-3.6.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-gef-sdk-3.6.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-gef-sdk-3.6.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-jdt-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-jdt-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-linuxprofilingframework-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-linuxprofilingframework-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-mylyn-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-mylyn-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-mylyn-cdt-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-mylyn-cdt-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-mylyn-java-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-mylyn-java-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-mylyn-pde-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-mylyn-pde-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-mylyn-trac-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-mylyn-trac-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-mylyn-webtasks-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-mylyn-webtasks-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-mylyn-wikitext-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-mylyn-wikitext-3.4.2-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-oprofile-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-oprofile-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-oprofile-debuginfo-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-oprofile-debuginfo-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-pde-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-pde-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-platform-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-platform-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-rcp-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-rcp-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-rse-3.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-rse-3.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-swt-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-swt-3.6.1-6.13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"eclipse-valgrind-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"eclipse-valgrind-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"icu4j-4.2.1-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"icu4j-4.2.1-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"icu4j-eclipse-4.2.1-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"icu4j-eclipse-4.2.1-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"icu4j-javadoc-4.2.1-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"icu4j-javadoc-4.2.1-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jetty-eclipse-6.1.24-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"objectweb-asm-3.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"objectweb-asm-javadoc-3.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sat4j-2.2.0-4.0.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eclipse-birt / eclipse-callgraph / eclipse-cdt / etc");
  }
}
