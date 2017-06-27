#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0329. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38870);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2006-1861", "CVE-2007-2754", "CVE-2008-1808", "CVE-2009-0946");
  script_bugtraq_id(24074, 29637, 29639, 34550);
  script_xref(name:"RHSA", value:"2009:0329");

  script_name(english:"RHEL 3 / 4 : freetype (RHSA-2009:0329)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix various security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently. These packages provide both the FreeType 1 and
FreeType 2 font engines.

Tavis Ormandy of the Google Security Team discovered several integer
overflow flaws in the FreeType 2 font engine. If a user loaded a
carefully-crafted font file with an application linked against
FreeType 2, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2009-0946)

Chris Evans discovered multiple integer overflow flaws in the FreeType
font engine. If a user loaded a carefully-crafted font file with an
application linked against FreeType, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2006-1861)

An integer overflow flaw was found in the way the FreeType font engine
processed TrueType(r) Font (TTF) files. If a user loaded a
carefully-crafted font file with an application linked against
FreeType, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2007-2754)

A flaw was discovered in the FreeType TTF font-file format parser when
the TrueType virtual machine Byte Code Interpreter (BCI) is enabled.
If a user loaded a carefully-crafted font file with an application
linked against FreeType, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2008-1808)

The CVE-2008-1808 flaw did not affect the freetype packages as
distributed in Red Hat Enterprise Linux 3 and 4, as they are not
compiled with TrueType BCI support. A fix for this flaw has been
included in this update as users may choose to recompile the freetype
packages in order to enable TrueType BCI support. Red Hat does not,
however, provide support for modified and recompiled packages.

Note: For the FreeType 2 font engine, the CVE-2006-1861,
CVE-2007-2754, and CVE-2008-1808 flaws were addressed via
RHSA-2006:0500, RHSA-2007:0403, and RHSA-2008:0556 respectively. This
update provides corresponding updates for the FreeType 1 font engine,
included in the freetype packages distributed in Red Hat Enterprise
Linux 3 and 4.

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1861.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2754.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0946.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/support/policy/soc/production/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0329.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0329";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL3", reference:"freetype-2.1.4-12.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"freetype-devel-2.1.4-12.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"freetype-2.1.9-10.el4.7")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-demos-2.1.9-10.el4.7")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-devel-2.1.9-10.el4.7")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-utils-2.1.9-10.el4.7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype / freetype-demos / freetype-devel / freetype-utils");
  }
}
