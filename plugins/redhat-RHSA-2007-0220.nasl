#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0220. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25137);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:20 $");

  script_cve_id("CVE-2006-3619");
  script_xref(name:"RHSA", value:"2007:0220");

  script_name(english:"RHEL 4 : gcc (RHSA-2007:0220)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gcc packages that fix a security issue and various bugs are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gcc packages include C, C++, Java, Fortran 77, Objective C, and
Ada 95 GNU compilers and related support libraries.

Jurgen Weigert discovered a directory traversal flaw in fastjar. An
attacker could create a malicious JAR file which, if unpacked using
fastjar, could write to any files the victim had write access to.
(CVE-2006-3619)

These updated packages also fix several bugs, including :

* two debug information generator bugs

* two internal compiler errors

In addition to this, protoize.1 and unprotoize.1 manual pages have
been added to the package and __cxa_get_exception_ptr@@CXXABI_1.3.1
symbol has been added into libstdc++.so.6.

For full details regarding all fixed bugs, refer to the package
changelog as well as the specified list of bug reports from bugzilla.

All users of gcc should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-3619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0220.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-g77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libf2c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0220";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL4", reference:"cpp-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"gcc-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"gcc-c++-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"gcc-g77-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"gcc-gnat-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"gcc-gnat-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"gcc-gnat-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"gcc-java-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"gcc-objc-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"libf2c-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"libgcc-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"libgcj-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"libgcj-devel-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libgnat-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"libgnat-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libgnat-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"libobjc-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"libstdc++-3.4.6-8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"libstdc++-devel-3.4.6-8")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-c++ / gcc-g77 / gcc-gnat / gcc-java / gcc-objc / etc");
  }
}
