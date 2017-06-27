#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0496. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90141);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_xref(name:"RHSA", value:"2016:0496");

  script_name(english:"RHEL 6 / 7 : git (RHSA-2016:0496)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated git packages that fix two security issues are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Git is a distributed revision control system with a decentralized
architecture. As opposed to centralized version control systems with a
client-server model, Git ensures that each working copy of a Git
repository is an exact copy with complete revision history. This not
only allows the user to work on and contribute to projects without the
need to have permission to push the changes to their official
repositories, but also makes it possible for the user to work with no
network connection.

An integer truncation flaw and an integer overflow flaw, both leading
to a heap-based buffer overflow, were found in the way Git processed
certain path information. A remote attacker could create a specially
crafted Git repository that would cause a Git client or server to
crash or, possibly, execute arbitrary code. (CVE-2016-2315,
CVE-2016-2324)

All git users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2315.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2324.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2201201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0496.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0496";
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
  if (rpm_check(release:"RHEL6", reference:"emacs-git-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"emacs-git-el-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-all-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-cvs-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-daemon-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-daemon-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-daemon-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-debuginfo-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-debuginfo-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-debuginfo-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-email-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-gui-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-svn-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gitk-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gitweb-1.7.1-4.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"perl-Git-1.7.1-4.el6_7.1")) flag++;


  if (rpm_check(release:"RHEL7", reference:"emacs-git-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"emacs-git-el-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-all-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-bzr-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-cvs-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-daemon-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-debuginfo-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-debuginfo-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-email-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-gui-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-hg-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-p4-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-svn-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-svn-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gitk-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gitweb-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"perl-Git-1.8.3.1-6.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"perl-Git-SVN-1.8.3.1-6.el7_2.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
  }
}
