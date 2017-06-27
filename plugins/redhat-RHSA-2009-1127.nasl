#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1127. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39529);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
  script_bugtraq_id(35271, 35309, 35318);
  script_xref(name:"RHSA", value:"2009:1127");

  script_name(english:"RHEL 4 / 5 : kdelibs (RHSA-2009:1127)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The kdelibs packages provide libraries for the K Desktop Environment
(KDE).

A flaw was found in the way the KDE CSS parser handled content for the
CSS 'style' attribute. A remote attacker could create a specially
crafted CSS equipped HTML page, which once visited by an unsuspecting
user, could cause a denial of service (Konqueror crash) or,
potentially, execute arbitrary code with the privileges of the user
running Konqueror. (CVE-2009-1698)

A flaw was found in the way the KDE HTML parser handled content for
the HTML 'head' element. A remote attacker could create a specially
crafted HTML page, which once visited by an unsuspecting user, could
cause a denial of service (Konqueror crash) or, potentially, execute
arbitrary code with the privileges of the user running Konqueror.
(CVE-2009-1690)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the KDE JavaScript garbage collector handled memory
allocation requests. A remote attacker could create a specially
crafted HTML page, which once visited by an unsuspecting user, could
cause a denial of service (Konqueror crash) or, potentially, execute
arbitrary code with the privileges of the user running Konqueror.
(CVE-2009-1687)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1127.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kdelibs, kdelibs-apidocs and / or kdelibs-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/26");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1127";
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
  if (rpm_check(release:"RHEL4", reference:"kdelibs-3.3.1-14.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kdelibs-devel-3.3.1-14.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"kdelibs-3.5.4-22.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kdelibs-apidocs-3.5.4-22.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kdelibs-apidocs-3.5.4-22.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kdelibs-apidocs-3.5.4-22.el5_3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"kdelibs-devel-3.5.4-22.el5_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-apidocs / kdelibs-devel");
  }
}
