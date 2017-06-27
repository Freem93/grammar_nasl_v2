#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0414 and 
# Oracle Linux Security Advisory ELSA-2011-0414 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68246);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2011-1011");
  script_bugtraq_id(46510);
  script_osvdb_id(72541);
  script_xref(name:"RHSA", value:"2011:0414");

  script_name(english:"Oracle Linux 6 : policycoreutils (ELSA-2011-0414)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0414 :

Updated policycoreutils packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The policycoreutils packages contain the core utilities that are
required for the basic operation of a Security-Enhanced Linux
(SELinux) system and its policies.

It was discovered that the seunshare utility did not enforce proper
file permissions on the directory used as an alternate temporary
directory mounted as /tmp/. A local user could use this flaw to
overwrite files or, possibly, execute arbitrary code with the
privileges of a setuid or setgid application that relies on proper
/tmp/ permissions, by running that application via seunshare.
(CVE-2011-1011)

Red Hat would like to thank Tavis Ormandy for reporting this issue.

This update also introduces the following changes :

* The seunshare utility was moved from the main policycoreutils
subpackage to the policycoreutils-sandbox subpackage. This utility is
only required by the sandbox feature and does not need to be installed
by default.

* Updated selinux-policy packages that add the SELinux policy changes
required by the seunshare fixes.

All policycoreutils users should upgrade to these updated packages,
which correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002055.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected policycoreutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-minimum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-mls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"policycoreutils-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"policycoreutils-gui-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"policycoreutils-newrole-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"policycoreutils-python-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"policycoreutils-sandbox-2.0.83-19.8.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"selinux-policy-3.7.19-54.0.1.el6_0.5")) flag++;
if (rpm_check(release:"EL6", reference:"selinux-policy-doc-3.7.19-54.0.1.el6_0.5")) flag++;
if (rpm_check(release:"EL6", reference:"selinux-policy-minimum-3.7.19-54.0.1.el6_0.5")) flag++;
if (rpm_check(release:"EL6", reference:"selinux-policy-mls-3.7.19-54.0.1.el6_0.5")) flag++;
if (rpm_check(release:"EL6", reference:"selinux-policy-targeted-3.7.19-54.0.1.el6_0.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils / policycoreutils-gui / policycoreutils-newrole / etc");
}
