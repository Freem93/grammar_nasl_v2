#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1797. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93269);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/10 20:46:32 $");

  script_cve_id("CVE-2016-5404");
  script_osvdb_id(143245);
  script_xref(name:"RHSA", value:"2016:1797");

  script_name(english:"RHEL 6 / 7 : ipa (RHSA-2016:1797)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ipa is now available for Red Hat Enterprise Linux 6 and
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Security Fix(es) :

* An insufficient permission check issue was found in the way IPA
server treats certificate revocation requests. An attacker logged in
with the 'retrieve certificate' permission enabled could use this flaw
to revoke certificates, possibly triggering a denial of service
attack. (CVE-2016-5404)

This issue was discovered by Fraser Tweedale (Red Hat)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1797.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
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
  rhsa = "RHSA-2016:1797";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-admintools-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-admintools-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-admintools-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-client-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-client-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-client-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-debuginfo-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-debuginfo-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-debuginfo-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-python-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-python-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-python-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-selinux-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-selinux-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-trust-ad-3.0.0-50.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-trust-ad-3.0.0-50.el6_8.2")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-admintools-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-admintools-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-client-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-client-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-debuginfo-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-debuginfo-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-python-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-python-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-server-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-server-dns-4.2.0-15.el7_2.19")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.2.0-15.el7_2.19")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-debuginfo / ipa-python / etc");
  }
}
