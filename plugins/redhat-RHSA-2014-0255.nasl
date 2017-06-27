#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0255. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72854);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:40:56 $");

  script_cve_id("CVE-2013-1968", "CVE-2013-2112", "CVE-2014-0032");
  script_bugtraq_id(60264, 60267, 65434);
  script_osvdb_id(102927);
  script_xref(name:"RHSA", value:"2014:0255");

  script_name(english:"RHEL 5 / 6 : subversion (RHSA-2014:0255)");
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
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

A flaw was found in the way the mod_dav_svn module handled OPTIONS
requests. A remote attacker with read access to an SVN repository
served via HTTP could use this flaw to cause the httpd process that
handled such a request to crash. (CVE-2014-0032)

A flaw was found in the way Subversion handled file names with newline
characters when the FSFS repository format was used. An attacker with
commit access to an SVN repository could corrupt a revision by
committing a specially crafted file. (CVE-2013-1968)

A flaw was found in the way the svnserve tool of Subversion handled
remote client network connections. An attacker with read access to an
SVN repository served via svnserve could use this flaw to cause the
svnserve daemon to exit, leading to a denial of service.
(CVE-2013-2112)

All subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, for the update to take effect, you must restart
the httpd daemon, if you are using mod_dav_svn, and the svnserve
daemon, if you are serving Subversion repositories via the svn://
protocol."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1968.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2014-0032-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2013-1968-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2013-2112-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0255.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2014:0255";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_dav_svn-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_dav_svn-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_dav_svn-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"subversion-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"subversion-debuginfo-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", reference:"subversion-devel-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subversion-javahl-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subversion-javahl-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subversion-javahl-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subversion-perl-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subversion-perl-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subversion-perl-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"subversion-ruby-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"subversion-ruby-1.6.11-12.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"subversion-ruby-1.6.11-12.el5_10")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_dav_svn-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_dav_svn-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_dav_svn-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-debuginfo-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-devel-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-gnome-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-javahl-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-kde-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-perl-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-ruby-1.6.11-10.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-svn2cl-1.6.11-10.el6_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-debuginfo / subversion-devel / etc");
  }
}
