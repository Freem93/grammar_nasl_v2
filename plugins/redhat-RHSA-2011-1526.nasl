#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1526. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57011);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2009-5064", "CVE-2011-1089");
  script_bugtraq_id(46740);
  script_osvdb_id(74278, 74883);
  script_xref(name:"RHSA", value:"2011:1526");

  script_name(english:"RHEL 6 : glibc (RHSA-2011:1526)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

A flaw was found in the way the ldd utility identified dynamically
linked libraries. If an attacker could trick a user into running ldd
on a malicious binary, it could result in arbitrary code execution
with the privileges of the user running ldd. (CVE-2009-5064)

It was found that the glibc addmntent() function, used by various
mount helper utilities, did not handle certain errors correctly when
updating the mtab (mounted file systems table) file. If such utilities
had the setuid bit set, a local attacker could use this flaw to
corrupt the mtab file. (CVE-2011-1089)

Red Hat would like to thank Dan Rosenberg for reporting the
CVE-2011-1089 issue.

This update also fixes several bugs and adds various enhancements.
Documentation for these bug fixes and enhancements will be available
shortly from the Technical Notes document, linked to in the References
section.

Users are advised to upgrade to these updated glibc packages, which
contain backported patches to resolve these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-5064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1526.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1526";
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
  if (rpm_check(release:"RHEL6", reference:"glibc-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-common-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-common-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-common-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-common-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-devel-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-headers-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-headers-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-headers-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glibc-static-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-utils-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-utils-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-utils-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nscd-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nscd-2.12-1.47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nscd-2.12-1.47.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
  }
}
