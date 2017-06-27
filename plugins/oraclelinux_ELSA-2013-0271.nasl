#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0271 and 
# Oracle Linux Security Advisory ELSA-2013-0271 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68732);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");
  script_bugtraq_id(58037, 58042, 58043, 58044, 58047);
  script_osvdb_id(90421, 90422, 90423, 90429, 90430);
  script_xref(name:"RHSA", value:"2013:0271");

  script_name(english:"Oracle Linux 5 / 6 : firefox (ELSA-2013-0271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0271 :

Updated firefox packages that fix several security issues are now
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
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003267.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003268.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"devhelp-0.12-23.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"devhelp-devel-0.12-23.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"firefox-17.0.3-1.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-17.0.3-1.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-17.0.3-1.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"yelp-2.16.0-30.el5_9")) flag++;

if (rpm_check(release:"EL6", reference:"firefox-17.0.3-1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-bin-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-devel-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-gnome-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-kde-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-mozjs-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-python-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libproxy-webkit-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"xulrunner-17.0.3-1.0.2.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"xulrunner-devel-17.0.3-1.0.2.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"yelp-2.28.1-17.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / firefox / libproxy / libproxy-bin / etc");
}
