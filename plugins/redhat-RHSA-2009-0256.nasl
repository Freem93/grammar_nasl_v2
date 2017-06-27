#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0256. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35585);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:16:35 $");

  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
  script_bugtraq_id(33598);
  script_osvdb_id(51925, 51926, 51927, 51928, 51929, 51930, 51931, 51932, 51933, 51934, 51935, 51936, 51937, 51938, 51939, 51940);
  script_xref(name:"RHSA", value:"2009:0256");

  script_name(english:"RHEL 4 / 5 : firefox (RHSA-2009:0256)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that fixes various security issues is now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2009-0352, CVE-2009-0353, CVE-2009-0356)

Several flaws were found in the way malformed content was processed. A
website containing specially crafted content could, potentially, trick
a Firefox user into surrendering sensitive information.
(CVE-2009-0354, CVE-2009-0355)

A flaw was found in the way Firefox treated HTTPOnly cookies. An
attacker able to execute arbitrary JavaScript on a target site using
HTTPOnly cookies may be able to use this flaw to steal the cookie.
(CVE-2009-0357)

A flaw was found in the way Firefox treated certain HTTP page caching
directives. A local attacker could steal the contents of sensitive
pages which the page author did not intend to be cached.
(CVE-2009-0358)

For technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 3.0.6. You can find a link to the
Mozilla advisories in the References section.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.0.6, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0354.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0356.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0357.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0358.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0256.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/04");
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
  rhsa = "RHSA-2009:0256";
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
  if (rpm_check(release:"RHEL4", reference:"firefox-3.0.6-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-3.12.2.0-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-devel-3.12.2.0-3.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-tools-3.12.2.0-3.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"firefox-3.0.6-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-3.12.2.0-4.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-devel-3.12.2.0-4.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-pkcs11-devel-3.12.2.0-4.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nss-tools-3.12.2.0-4.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nss-tools-3.12.2.0-4.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nss-tools-3.12.2.0-4.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-1.9.0.6-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-devel-1.9.0.6-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xulrunner-devel-unstable-1.9.0.6-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"xulrunner-devel-unstable-1.9.0.6-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xulrunner-devel-unstable-1.9.0.6-1.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / nss / nss-devel / nss-pkcs11-devel / nss-tools / etc");
  }
}
