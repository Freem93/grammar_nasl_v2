#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0039 and 
# Oracle Linux Security Advisory ELSA-2010-0039 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67985);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:49:13 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"RHSA", value:"2010:0039");

  script_name(english:"Oracle Linux 3 / 4 / 5 : gcc / gcc4 (ELSA-2010-0039)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0039 :

Updated gcc and gcc4 packages that fix one security issue are now
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
    value:"https://oss.oracle.com/pipermail/el-errata/2010-January/001317.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-January/001319.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-January/001320.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gcc and / or gcc4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-g77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc4-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc4-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libf2c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcj-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcj4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcj4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcj4-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cpp-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cpp-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gcc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gcc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gcc-c++-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gcc-c++-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gcc-g77-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gcc-g77-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gcc-gnat-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gcc-gnat-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gcc-java-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gcc-java-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gcc-objc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gcc-objc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libf2c-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libf2c-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libgcc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libgcc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libgcj-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libgcj-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libgcj-devel-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libgcj-devel-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libgnat-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libgnat-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libobjc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libobjc-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libstdc++-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libstdc++-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libstdc++-devel-3.2.3-60")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libstdc++-devel-3.2.3-60")) flag++;

if (rpm_check(release:"EL4", reference:"cpp-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc-c++-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc-g77-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc-gnat-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc-java-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc-objc-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc4-c++-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc4-gfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"gcc4-java-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libf2c-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgcc-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgcj-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgcj-devel-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgcj4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgcj4-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgcj4-src-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgnat-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libgomp-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libmudflap-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libmudflap-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libobjc-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libstdc++-3.4.6-11.0.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libstdc++-devel-3.4.6-11.0.1.el4_8.1")) flag++;

if (rpm_check(release:"EL5", reference:"cpp-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"gcc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"gcc-c++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"gcc-gfortran-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"gcc-gnat-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"gcc-java-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"gcc-objc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"gcc-objc++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libgcc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libgcj-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libgcj-devel-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libgcj-src-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libgfortran-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libgnat-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libmudflap-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libmudflap-devel-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libobjc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libstdc++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"libstdc++-devel-4.1.2-46.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-c++ / gcc-g77 / gcc-gfortran / gcc-gnat / gcc-java / etc");
}
