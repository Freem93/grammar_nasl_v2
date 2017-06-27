#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0165. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81292);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-3528", "CVE-2014-3580");
  script_osvdb_id(109748, 115922);
  script_xref(name:"RHSA", value:"2015:0165");

  script_name(english:"RHEL 6 : subversion (RHSA-2015:0165)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module handled REPORT requests. A remote, unauthenticated attacker
could use a specially crafted REPORT request to crash mod_dav_svn.
(CVE-2014-3580)

It was discovered that Subversion clients retrieved cached
authentication credentials using the MD5 hash of the server realm
string without also checking the server's URL. A malicious server able
to provide a realm that triggers an MD5 collision could possibly use
this flaw to obtain the credentials for a different realm.
(CVE-2014-3528)

Red Hat would like to thank the Subversion project for reporting
CVE-2014-3580. Upstream acknowledges Evgeny Kotkov of VisualSVN as the
original reporter.

All subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, for the update to take effect, you must restart
the httpd daemon, if you are using mod_dav_svn, and the svnserve
daemon, if you are serving Subversion repositories via the svn://
protocol."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3528.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3580.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2014-3528-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2014-3580-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0165.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:0165";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_dav_svn-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_dav_svn-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_dav_svn-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-debuginfo-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-devel-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-gnome-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-javahl-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-kde-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-perl-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-ruby-1.6.11-12.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"subversion-svn2cl-1.6.11-12.el6_6")) flag++;


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
