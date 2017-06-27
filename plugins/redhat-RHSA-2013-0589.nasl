#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0589. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65006);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2013-0308");
  script_bugtraq_id(58148);
  script_osvdb_id(90610);
  script_xref(name:"RHSA", value:"2013:0589");

  script_name(english:"RHEL 6 : git (RHSA-2013:0589)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated git packages that fix one security issue are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Git is a fast, scalable, distributed revision control system.

It was discovered that Git's git-imap-send command, a tool to send a
collection of patches from standard input (stdin) to an IMAP folder,
did not properly perform SSL X.509 v3 certificate validation on the
IMAP server's certificate, as it did not ensure that the server's
hostname matched the one provided in the CN field of the server's
certificate. A rogue server could use this flaw to conduct
man-in-the-middle attacks, possibly leading to the disclosure of
sensitive information. (CVE-2013-0308)

All git users should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0308.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0589.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0589";
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
  if (rpm_check(release:"RHEL6", reference:"emacs-git-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"emacs-git-el-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-all-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-cvs-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-daemon-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-daemon-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-daemon-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"git-debuginfo-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"git-debuginfo-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"git-debuginfo-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-email-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-gui-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"git-svn-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gitk-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gitweb-1.7.1-3.el6_4.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"perl-Git-1.7.1-3.el6_4.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-cvs / git-daemon / etc");
  }
}
