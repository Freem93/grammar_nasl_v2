#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:053. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12462);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2004-0107", "CVE-2004-0108");
  script_xref(name:"RHSA", value:"2004:053");

  script_name(english:"RHEL 2.1 / 3 : sysstat (RHSA-2004:053)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sysstat packages that fix various bugs and security issues are
now available.

Sysstat is a tool for gathering system statistics. Isag is a utility
for graphically displaying these statistics.

A bug was found in the Red Hat sysstat package post and trigger
scripts, which used insecure temporary file names. A local attacker
could overwrite system files using carefully-crafted symbolic links in
the /tmp directory. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0107 to this issue.

While fixing this issue, a flaw was discovered in the isag utility,
which also used insecure temporary file names. A local attacker could
overwrite files that the user running isag has write access to using
carefully-crafted symbolic links in the /tmp directory. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0108 to this issue.

Other issues addressed in this advisory include :

* iostat -x should return all partitions on the system (up to a
maximum of 1024)

* sar should handle network device names with more than 8 characters
properly

* mpstat should work correctly with more than 7 CPUs as well as
generate correct statistics when accessing individual CPUs. This issue
only affected Red Hat Enterprise Linux 2.1

* The sysstat package was not built with the proper dependencies;
therefore, it was possible that isag could not be run because the
necessary tools were not available. Therefore, isag was split off into
its own subpackage with the required dependencies in place. This issue
only affects Red Hat Enterprise Linux 2.1.

Users of sysstat and isag should upgrade to these updated packages,
which contain patches to correct these issues.

NOTE: In order to use isag on Red Hat Enterprise Linux 2.1, you must
install the sysstat-isag package after upgrading."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0108.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-053.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sysstat and / or sysstat-isag packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sysstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sysstat-isag");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:053";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sysstat-4.0.1-12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sysstat-isag-4.0.1-12")) flag++;

  if (rpm_check(release:"RHEL3", reference:"sysstat-4.0.7-4.EL3.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sysstat / sysstat-isag");
  }
}
