#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0862. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55016);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_bugtraq_id(48091);
  script_osvdb_id(73245, 73246, 73247);
  script_xref(name:"RHSA", value:"2011:0862");

  script_name(english:"RHEL 5 / 6 : subversion (RHSA-2011:0862)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix three security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

An infinite loop flaw was found in the way the mod_dav_svn module
processed certain data sets. If the SVNPathAuthz directive was set to
'short_circuit', and path-based access control for files and
directories was enabled, a malicious, remote user could use this flaw
to cause the httpd process serving the request to consume an excessive
amount of system memory. (CVE-2011-1783)

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module processed requests submitted against the URL of a baselined
resource. A malicious, remote user could use this flaw to cause the
httpd process serving the request to crash. (CVE-2011-1752)

An information disclosure flaw was found in the way the mod_dav_svn
module processed certain URLs when path-based access control for files
and directories was enabled. A malicious, remote user could possibly
use this flaw to access certain files in a repository that would
otherwise not be accessible to them. Note: This vulnerability cannot
be triggered if the SVNPathAuthz directive is set to 'short_circuit'.
(CVE-2011-1921)

Red Hat would like to thank the Apache Subversion project for
reporting these issues. Upstream acknowledges Joe Schaefer of the
Apache Software Foundation as the original reporter of CVE-2011-1752;
Ivan Zhakov of VisualSVN as the original reporter of CVE-2011-1783;
and Kamesh Jayachandran of CollabNet, Inc. as the original reporter of
CVE-2011-1921.

All Subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, you must restart the httpd daemon, if you are
using mod_dav_svn, for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2011-1783-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2011-1752-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2011-1921-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0862.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subversion-svn2cl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:0862";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_dav_svn-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_dav_svn-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_dav_svn-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"subversion-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"subversion-devel-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subversion-javahl-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subversion-javahl-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subversion-javahl-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subversion-perl-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subversion-perl-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subversion-perl-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subversion-ruby-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subversion-ruby-1.6.11-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subversion-ruby-1.6.11-7.el5_6.4")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_dav_svn-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_dav_svn-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_dav_svn-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-debuginfo-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-devel-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-gnome-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-javahl-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-kde-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-perl-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-ruby-1.6.11-2.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-svn2cl-1.6.11-2.el6_1.4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-debuginfo / subversion-devel / etc");
  }
}
