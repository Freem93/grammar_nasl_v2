#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0597. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33528);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-3198");
  script_bugtraq_id(29802, 30242);
  script_osvdb_id(47465);
  script_xref(name:"RHSA", value:"2008:0597");

  script_name(english:"RHEL 5 : firefox (RHSA-2008:0597)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix various security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 16th July 2008] The nspluginwrapper package has been added to
this advisory to satisfy a missing package dependency issue.

Mozilla Firefox is an open source Web browser.

An integer overflow flaw was found in the way Firefox displayed
certain web content. A malicious website could cause Firefox to crash,
or execute arbitrary code with the permissions of the user running
Firefox. (CVE-2008-2785)

A flaw was found in the way Firefox handled certain command line URLs.
If another application passed Firefox a malformed URL, it could result
in Firefox executing local malicious content with chrome privileges.
(CVE-2008-2933)

All firefox users should upgrade to these updated packages, which
contain Firefox 3.0.1 that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2785.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2933.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3198.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0597.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspluginwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0597";
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
  if (rpm_check(release:"RHEL5", reference:"devhelp-0.12-18.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"devhelp-devel-0.12-18.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"firefox-3.0.1-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nspluginwrapper-0.9.91.5-22.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nspluginwrapper-0.9.91.5-22.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-1.9.0.1-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-devel-1.9.0.1-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xulrunner-devel-unstable-1.9.0.1-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"xulrunner-devel-unstable-1.9.0.1-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xulrunner-devel-unstable-1.9.0.1-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"yelp-2.16.0-20.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"yelp-2.16.0-20.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"yelp-2.16.0-20.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / firefox / nspluginwrapper / xulrunner / etc");
  }
}
