#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0271. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64696);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");
  script_osvdb_id(90421, 90422, 90423, 90429, 90430);
  script_xref(name:"RHSA", value:"2013:0271");

  script_name(english:"RHEL 5 / 6 : firefox (RHSA-2013:0271)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2013-0775, CVE-2013-0780, CVE-2013-0782,
CVE-2013-0783)

It was found that, after canceling a proxy server's authentication
prompt, the address bar continued to show the requested site's
address. An attacker could use this flaw to conduct phishing attacks
by tricking a user into believing they are viewing a trusted site.
(CVE-2013-0776)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Nils, Abhishek Arya, Olli Pettay,
Christoph Diehl, Gary Kwong, Jesse Ruderman, Andrew McCreight, Joe
Drew, Wayne Mery, and Michal Zalewski as the original reporters of
these issues.

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 17.0.3 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Note that due to a Kerberos credentials change, the following
configuration steps may be required when using Firefox 17.0.3 ESR with
the Enterprise Identity Management (IPA) web interface :

https://access.redhat.com/knowledge/solutions/294303

Important: Firefox 17 is not completely backwards-compatible with all
Mozilla add-ons and Firefox plug-ins that worked with Firefox 10.0.
Firefox 17 checks compatibility on first-launch, and, depending on the
individual configuration and the installed add-ons and plug-ins, may
disable said Add-ons and plug-ins, or attempt to check for updates and
upgrade them. Add-ons and plug-ins may have to be manually updated.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 17.0.3 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/firefoxESR.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/solutions/294303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0271.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libproxy-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0271";
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
  if (rpm_check(release:"RHEL5", reference:"devhelp-0.12-23.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"devhelp-debuginfo-0.12-23.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"devhelp-devel-0.12-23.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"firefox-17.0.3-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"firefox-debuginfo-17.0.3-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-17.0.3-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-debuginfo-17.0.3-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-devel-17.0.3-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"yelp-2.16.0-30.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"yelp-2.16.0-30.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"yelp-2.16.0-30.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"yelp-debuginfo-2.16.0-30.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"yelp-debuginfo-2.16.0-30.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"yelp-debuginfo-2.16.0-30.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", reference:"firefox-17.0.3-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"firefox-debuginfo-17.0.3-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libproxy-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libproxy-bin-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libproxy-bin-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libproxy-bin-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libproxy-debuginfo-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libproxy-devel-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libproxy-gnome-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libproxy-gnome-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libproxy-gnome-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libproxy-kde-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libproxy-kde-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libproxy-kde-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libproxy-mozjs-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libproxy-mozjs-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libproxy-mozjs-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libproxy-python-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libproxy-python-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libproxy-python-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libproxy-webkit-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libproxy-webkit-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libproxy-webkit-0.3.0-4.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-17.0.3-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-debuginfo-17.0.3-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-devel-17.0.3-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"yelp-2.28.1-17.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"yelp-2.28.1-17.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"yelp-2.28.1-17.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"yelp-debuginfo-2.28.1-17.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"yelp-debuginfo-2.28.1-17.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"yelp-debuginfo-2.28.1-17.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-debuginfo / devhelp-devel / firefox / etc");
  }
}
