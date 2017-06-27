#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0966. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51107);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/04 15:51:49 $");

  script_cve_id("CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777");
  script_bugtraq_id(45314, 45322, 45324, 45326, 45352, 45354);
  script_osvdb_id(69776);
  script_xref(name:"RHSA", value:"2010:0966");

  script_name(english:"RHEL 4 / 5 / 6 : firefox (RHSA-2010:0966)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-3766, CVE-2010-3767, CVE-2010-3772,
CVE-2010-3776, CVE-2010-3777)

A flaw was found in the way Firefox handled malformed JavaScript. A
website with an object containing malicious JavaScript could cause
Firefox to execute that JavaScript with the privileges of the user
running Firefox. (CVE-2010-3771)

This update adds support for the Sanitiser for OpenType (OTS) library
to Firefox. This library helps prevent potential exploits in malformed
OpenType fonts by verifying the font file prior to use.
(CVE-2010-3768)

A flaw was found in the way Firefox loaded Java LiveConnect scripts.
Malicious web content could load a Java LiveConnect script in a way
that would result in the plug-in object having elevated privileges,
allowing it to execute Java code with the privileges of the user
running Firefox. (CVE-2010-3775)

It was found that the fix for CVE-2010-0179 was incomplete when the
Firebug add-on was used. If a user visited a website containing
malicious JavaScript while the Firebug add-on was enabled, it could
cause Firefox to execute arbitrary JavaScript with the privileges of
the user running Firefox. (CVE-2010-3773)

A flaw was found in the way Firefox presented the location bar to
users. A malicious website could trick a user into thinking they are
visiting the site reported by the location bar, when the page is
actually content controlled by an attacker. (CVE-2010-3774)

A cross-site scripting (XSS) flaw was found in the Firefox
x-mac-arabic, x-mac-farsi, and x-mac-hebrew character encodings.
Certain characters were converted to angle brackets when displayed. If
server-side script filtering missed these cases, it could result in
Firefox executing JavaScript code with the permissions of a different
website. (CVE-2010-3770)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.13. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.13, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3766.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3768.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3770.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3771.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3773.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://code.google.com/p/ots/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0966.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0966";
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
  if (rpm_check(release:"RHEL4", reference:"firefox-3.6.13-3.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"firefox-3.6.13-2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-1.9.2.13-3.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-devel-1.9.2.13-3.el5")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"firefox-3.6.13-2.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"firefox-3.6.13-2.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"firefox-3.6.13-2.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"firefox-debuginfo-3.6.13-2.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"firefox-debuginfo-3.6.13-2.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"firefox-debuginfo-3.6.13-2.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-1.9.2.13-3.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-debuginfo-1.9.2.13-3.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-devel-1.9.2.13-3.el6_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo / xulrunner / xulrunner-debuginfo / etc");
  }
}
