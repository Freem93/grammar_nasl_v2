#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0501. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47119);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2008-5913", "CVE-2009-5017", "CVE-2010-0182", "CVE-2010-0183", "CVE-2010-1028", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-3171");
  script_osvdb_id(53341, 62416, 63457, 63479, 65734, 65735, 65739, 65742, 65744, 65749, 65750, 65751, 65752);
  script_xref(name:"RHSA", value:"2010:0501");

  script_name(english:"RHEL 5 : firefox (RHSA-2010:0501)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that address several security issues, fix
bugs, add numerous enhancements, and upgrade Firefox to version 3.6.4,
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

[Updated 25 June 2010] The original packages distributed with this
erratum had a bug which could cause unintended dependencies to be
installed when upgrading. We have updated the packages to correct this
bug.

Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-1121, CVE-2010-1200, CVE-2010-1202,
CVE-2010-1203)

A flaw was found in the way browser plug-ins interact. It was possible
for a plug-in to reference the freed memory from a different plug-in,
resulting in the execution of arbitrary code with the privileges of
the user running Firefox. (CVE-2010-1198)

Several integer overflow flaws were found in the processing of
malformed web content. A web page containing malicious content could
cause Firefox to crash or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2010-1196,
CVE-2010-1199)

A focus stealing flaw was found in the way Firefox handled focus
changes. A malicious website could use this flaw to steal sensitive
data from a user, such as usernames and passwords. (CVE-2010-1125)

A flaw was found in the way Firefox handled the 'Content-Disposition:
attachment' HTTP header when the 'Content-Type: multipart' HTTP header
was also present. A website that allows arbitrary uploads and relies
on the 'Content-Disposition: attachment' HTTP header to prevent
content from being displayed inline, could be used by an attacker to
serve malicious content to users. (CVE-2010-1197)

A flaw was found in the Firefox Math.random() function. This function
could be used to identify a browsing session and track a user across
different websites. (CVE-2008-5913)

A flaw was found in the Firefox XML document loading security checks.
Certain security checks were not being called when an XML document was
loaded. This could possibly be leveraged later by an attacker to load
certain resources that violate the security policies of the browser or
its add-ons. Note that this issue cannot be exploited by only loading
an XML document. (CVE-2010-0182)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.4. You can find a link to the
Mozilla advisories in the References section of this erratum.

This erratum upgrades Firefox from version 3.0.19 to version 3.6.4.
Due to the requirements of Firefox 3.6.4, this erratum also provides a
number of other updated packages, including esc, totem, and yelp.

This erratum also contains multiple bug fixes and numerous
enhancements. Space precludes documenting these changes in this
advisory. For details concerning these changes, refer to the Firefox
Release Notes links in the References section of this erratum.

Important: Firefox 3.6.4 is not completely backwards-compatible with
all Mozilla Add-ons and Firefox plug-ins that worked with Firefox
3.0.19. Firefox 3.6 checks compatibility on first-launch, and,
depending on the individual configuration and the installed Add-ons
and plug-ins, may disable said Add-ons and plug-ins, or attempt to
check for updates and upgrade them. Add-ons and plug-ins may have to
be manually updated.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.4. After installing the update, Firefox
must be restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-5017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1121.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1198.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1199.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mozilla.com/en-US/firefox/3.6.4/releasenotes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mozilla.com/en-US/firefox/3.6/releasenotes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mozilla.org/security/known-vulnerabilities/firefox35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0501.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:esc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-python2-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-python2-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-python2-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-python2-libegg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:totem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:totem-mozplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/23");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0501";
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
  if (rpm_check(release:"RHEL5", reference:"devhelp-0.12-21.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"devhelp-devel-0.12-21.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"esc-1.1.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"esc-1.1.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"firefox-3.6.4-8.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnome-python2-extras-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnome-python2-extras-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnome-python2-extras-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnome-python2-gtkhtml2-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnome-python2-gtkhtml2-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnome-python2-gtkhtml2-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnome-python2-gtkmozembed-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnome-python2-gtkmozembed-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnome-python2-gtkmozembed-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnome-python2-gtkspell-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnome-python2-gtkspell-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnome-python2-gtkspell-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnome-python2-libegg-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnome-python2-libegg-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnome-python2-libegg-2.14.2-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"totem-2.16.7-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"totem-devel-2.16.7-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"totem-mozplugin-2.16.7-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"totem-mozplugin-2.16.7-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"totem-mozplugin-2.16.7-7.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xulrunner-1.9.2.4-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xulrunner-devel-1.9.2.4-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"yelp-2.16.0-26.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"yelp-2.16.0-26.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"yelp-2.16.0-26.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / esc / firefox / gnome-python2-extras / etc");
  }
}
