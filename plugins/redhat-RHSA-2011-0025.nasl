#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0025. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51523);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2010-0831", "CVE-2010-2322");
  script_bugtraq_id(41006, 41009);
  script_xref(name:"RHSA", value:"2011:0025");

  script_name(english:"RHEL 5 : gcc (RHSA-2011:0025)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gcc packages that fix two security issues and several compiler
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The gcc packages include C, C++, Java, Fortran, Objective C, and Ada
95 GNU compilers, along with related support libraries. The libgcj
package provides fastjar, an archive tool for Java Archive (JAR)
files.

Two directory traversal flaws were found in the way fastjar extracted
JAR archive files. If a local, unsuspecting user extracted a specially
crafted JAR file, it could cause fastjar to overwrite arbitrary files
writable by the user running fastjar. (CVE-2010-0831, CVE-2010-2322)

This update also fixes the following bugs :

* The option -print-multi-os-directory in the gcc --help output is not
in the gcc(1) man page. This update applies an upstream patch to amend
this. (BZ#529659)

* An internal assertion in the compiler tried to check that a C++
static data member is external which resulted in errors. This was
because when the compiler optimizes C++ anonymous namespaces the
declarations were no longer marked external as everything on anonymous
namespaces is local to the current translation. This update corrects
the assertion to resolve this issue. (BZ#503565, BZ#508735, BZ#582682)

* Attempting to compile certain .cpp files could have resulted in an
internal compiler error. This update resolves this issue. (BZ#527510)

* PrintServiceLookup.lookupPrintServices with an appropriate DocFlavor
failed to return a list of printers under gcj. This update includes a
backported patch to correct this bug in the printer lookup service.
(BZ#578382)

* GCC would not build against xulrunner-devel-1.9.2. This update
removes gcjwebplugin from the GCC RPM. (BZ#596097)

* When a SystemTap generated kernel module was compiled, gcc reported
an internal compiler error and gets a segmentation fault. This update
applies a patch that, instead of crashing, assumes it can point to
anything. (BZ#605803)

* There was a performance issue with libstdc++ regarding all objects
derived from or using std::streambuf because of lock contention
between threads. This patch ensures reload uses the same value from
_S_global for the comparison, _M_add_reference () and _M_impl member
of the class. (BZ#635708)

All gcc users should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0025.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/14");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0025";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cpp-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cpp-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cpp-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-c++-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-c++-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-c++-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-gfortran-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-gfortran-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-gfortran-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-gnat-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-gnat-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-java-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-java-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-java-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-objc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-objc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-objc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-objc++-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-objc++-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-objc++-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libgcc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libgcj-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libgcj-devel-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libgcj-src-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"libgcj-src-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libgcj-src-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libgfortran-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libgnat-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libgnat-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libmudflap-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libmudflap-devel-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libobjc-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libstdc++-4.1.2-50.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"libstdc++-devel-4.1.2-50.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-c++ / gcc-gfortran / gcc-gnat / gcc-java / gcc-objc / etc");
  }
}
