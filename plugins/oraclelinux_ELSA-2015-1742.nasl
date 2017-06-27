#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1742 and 
# Oracle Linux Security Advisory ELSA-2015-1742 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85865);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/12/04 14:38:00 $");

  script_cve_id("CVE-2015-0248", "CVE-2015-0251", "CVE-2015-3184", "CVE-2015-3187");
  script_osvdb_id(120099, 120121, 125798, 125799);
  script_xref(name:"RHSA", value:"2015:1742");

  script_name(english:"Oracle Linux 7 : subversion (ELSA-2015-1742)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1742 :

Updated subversion packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

An assertion failure flaw was found in the way the SVN server
processed certain requests with dynamically evaluated revision
numbers. A remote attacker could use this flaw to cause the SVN server
(both svnserve and httpd with the mod_dav_svn module) to crash.
(CVE-2015-0248)

It was found that the mod_authz_svn module did not properly restrict
anonymous access to Subversion repositories under certain
configurations when used with Apache httpd 2.4.x. This could allow a
user to anonymously access files in a Subversion repository, which
should only be accessible to authenticated users. (CVE-2015-3184)

It was found that the mod_dav_svn module did not properly validate the
svn:author property of certain requests. An attacker able to create
new revisions could use this flaw to spoof the svn:author property.
(CVE-2015-0251)

It was found that when an SVN server (both svnserve and httpd with the
mod_dav_svn module) searched the history of a file or a directory, it
would disclose its location in the repository if that file or
directory was not readable (for example, if it had been moved).
(CVE-2015-3187)

Red Hat would like to thank the Apache Software Foundation for
reporting these issues. Upstream acknowledges Evgeny Kotkov of
VisualSVN as the original reporter of CVE-2015-0248 and CVE-2015-0251,
and C. Michael Pilato of CollabNet as the original reporter of
CVE-2015-3184 and CVE-2015-3187 flaws.

All subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, for the update to take effect, you must restart
the httpd daemon, if you are using mod_dav_svn, and the svnserve
daemon, if you are serving Subversion repositories via the svn://
protocol."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-September/005391.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_dav_svn-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-devel-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-gnome-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-javahl-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-kde-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-libs-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-perl-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-python-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-ruby-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-tools-1.7.14-7.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-gnome / etc");
}
