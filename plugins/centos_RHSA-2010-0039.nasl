#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0039 and 
# CentOS Errata and Security Advisory 2010:0039 respectively.
#

include("compat.inc");

if (description)
{
  script_id(44027);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"RHSA", value:"2010:0039");

  script_name(english:"CentOS 3 / 4 / 5 : gcc / gcc4 (CESA-2010:0039)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016445.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33faba81"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016446.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dd41757"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08ce4072"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48266381"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016459.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12650d5e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016460.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ed53088"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-g77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc4-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc4-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libf2c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj4-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cpp-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cpp-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gcc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gcc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gcc-c++-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gcc-c++-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gcc-g77-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gcc-g77-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gcc-gnat-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gcc-gnat-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gcc-java-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gcc-java-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gcc-objc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gcc-objc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libf2c-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libf2c-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libgcc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libgcc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libgcj-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libgcj-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libgcj-devel-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libgcj-devel-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libgnat-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libgnat-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libobjc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libobjc-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libstdc++-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libstdc++-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libstdc++-devel-3.2.3-60")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libstdc++-devel-3.2.3-60")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cpp-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cpp-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc-c++-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc-c++-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc-g77-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc-g77-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc-gnat-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc-gnat-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc-java-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc-java-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc-objc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc-objc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc4-c++-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc4-c++-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc4-gfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc4-gfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gcc4-java-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gcc4-java-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libf2c-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libf2c-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgcc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgcc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgcj-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgcj-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgcj-devel-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgcj-devel-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgcj4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgcj4-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgcj4-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgcj4-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgcj4-src-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgcj4-src-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgfortran-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgnat-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgnat-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libgomp-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libgomp-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libmudflap-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libmudflap-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libmudflap-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libmudflap-devel-4.1.2-44.EL4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libobjc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libobjc-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libstdc++-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libstdc++-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libstdc++-devel-3.4.6-11.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libstdc++-devel-3.4.6-11.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"cpp-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gcc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gcc-c++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gcc-gfortran-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gcc-gnat-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gcc-java-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gcc-objc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gcc-objc++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libgcc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libgcj-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libgcj-devel-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libgcj-src-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libgfortran-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libgnat-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libmudflap-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libmudflap-devel-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libobjc-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libstdc++-4.1.2-46.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libstdc++-devel-4.1.2-46.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
