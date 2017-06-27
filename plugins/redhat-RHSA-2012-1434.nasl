#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1434. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62857);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-4540");
  script_osvdb_id(87249);
  script_xref(name:"RHSA", value:"2012:1434");

  script_name(english:"RHEL 6 : icedtea-web (RHSA-2012:1434)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated icedtea-web packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The IcedTea-Web project provides a Java web browser plug-in and an
implementation of Java Web Start, which is based on the Netx project.
It also contains a configuration tool for managing deployment settings
for the plug-in and Web Start implementations.

A buffer overflow flaw was found in the IcedTea-Web plug-in. Visiting
a malicious web page could cause a web browser using the IcedTea-Web
plug-in to crash or, possibly, execute arbitrary code. (CVE-2012-4540)

Red Hat would like to thank Arthur Gerkis for reporting this issue.

This erratum also upgrades IcedTea-Web to version 1.2.2. Refer to the
NEWS file, linked to in the References, for further information.

All IcedTea-Web users should upgrade to these updated packages, which
resolve this issue. Web browsers using the IcedTea-Web browser plug-in
must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4540.html"
  );
  # http://icedtea.classpath.org/hg/release/icedtea-web-1.2/file/icedtea-web-1.2.2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5946ddb1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://icedtea.classpath.org/hg/release/icedtea-web-1.2/file/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected icedtea-web, icedtea-web-debuginfo and / or
icedtea-web-javadoc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1434";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"icedtea-web-1.2.2-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"icedtea-web-1.2.2-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"icedtea-web-debuginfo-1.2.2-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"icedtea-web-debuginfo-1.2.2-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"icedtea-web-javadoc-1.2.2-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"icedtea-web-javadoc-1.2.2-1.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-debuginfo / icedtea-web-javadoc");
  }
}
