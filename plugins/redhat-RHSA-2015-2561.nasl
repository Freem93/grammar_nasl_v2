#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2561. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87275);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/06 16:11:33 $");

  script_cve_id("CVE-2015-7545");
  script_osvdb_id(128629);
  script_xref(name:"RHSA", value:"2015:2561");

  script_name(english:"RHEL 7 : git (RHSA-2015:2561)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated git packages that fix one security issue are now available for
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Git is a distributed revision control system with a decentralized
architecture. As opposed to centralized version control systems with a
client-server model, Git ensures that each working copy of a Git
repository is an exact copy with complete revision history. This not
only allows the user to work on and contribute to projects without the
need to have permission to push the changes to their official
repositories, but also makes it possible for the user to work with no
network connection.

A flaw was found in the way the git-remote-ext helper processed
certain URLs. If a user had Git configured to automatically clone
submodules from untrusted repositories, an attacker could inject
commands into the URL of a submodule, allowing them to execute
arbitrary code on the user's system. (BZ#1269794)

All git users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2561.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/09");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2561";
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
  if (rpm_check(release:"RHEL7", reference:"emacs-git-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"emacs-git-el-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-all-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-bzr-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-cvs-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-daemon-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-daemon-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-debuginfo-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-debuginfo-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-email-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-gui-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-hg-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"git-p4-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"git-svn-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"git-svn-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gitk-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gitweb-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"perl-Git-1.8.3.1-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"perl-Git-SVN-1.8.3.1-6.el7")) flag++;


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
