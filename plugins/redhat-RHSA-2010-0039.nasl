#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0039. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43882);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/04 15:51:46 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"RHSA", value:"2010:0039");

  script_name(english:"RHEL 3 / 4 / 5 : gcc and gcc4 (RHSA-2010:0039)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gcc and gcc4 packages that fix one security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gcc and gcc4 packages include, among others, C, C++, and Java GNU
compilers and related support libraries. libgcj contains a copy of GNU
Libtool's libltdl library.

A flaw was found in the way GNU Libtool's libltdl library looked for
libraries to load. It was possible for libltdl to load a malicious
library from the current working directory. In certain configurations,
if a local attacker is able to trick a local user into running a Java
application (which uses a function to load native libraries, such as
System.loadLibrary) from within an attacker-controlled directory
containing a malicious library or module, the attacker could possibly
execute arbitrary code with the privileges of the user running the
Java application. (CVE-2009-3736)

All gcc and gcc4 users should upgrade to these updated packages, which
contain a backported patch to correct this issue. All running Java
applications using libgcj must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0039.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-g77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc4-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc4-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libf2c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj4-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0039";
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
  if (rpm_check(release:"RHEL3", reference:"cpp-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gcc-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gcc-c++-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gcc-g77-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"gcc-gnat-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"gcc-gnat-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"gcc-gnat-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gcc-java-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gcc-objc-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libf2c-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libgcc-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libgcj-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libgcj-devel-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"libgnat-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"libgnat-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"libgnat-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libobjc-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libstdc++-3.2.3-60")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libstdc++-devel-3.2.3-60")) flag++;


  if (rpm_check(release:"RHEL4", reference:"cpp-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc-c++-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc-g77-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"gcc-gnat-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"gcc-gnat-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"gcc-gnat-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc-java-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc-objc-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc4-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc4-c++-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc4-gfortran-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gcc4-java-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libf2c-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgcc-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgcj-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgcj-devel-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgcj4-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgcj4-devel-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgcj4-src-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgfortran-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libgnat-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"libgnat-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libgnat-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libgomp-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libmudflap-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libmudflap-devel-4.1.2-44.EL4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libobjc-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libstdc++-3.4.6-11.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libstdc++-devel-3.4.6-11.el4_8.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cpp-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cpp-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cpp-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-c++-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-c++-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-c++-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-gfortran-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-gfortran-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-gfortran-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-gnat-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-gnat-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-java-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-java-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-java-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-objc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-objc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-objc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gcc-objc++-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gcc-objc++-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gcc-objc++-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libgcc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libgcj-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libgcj-devel-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libgcj-src-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"libgcj-src-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libgcj-src-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libgfortran-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libgnat-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libgnat-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libmudflap-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libmudflap-devel-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libobjc-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libstdc++-4.1.2-46.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libstdc++-devel-4.1.2-46.el5_4.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-c++ / gcc-g77 / gcc-gfortran / gcc-gnat / gcc-java / etc");
  }
}
