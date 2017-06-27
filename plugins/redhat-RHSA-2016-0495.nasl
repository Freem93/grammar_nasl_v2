#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0495. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90140);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2016-1950");
  script_osvdb_id(135603);
  script_xref(name:"RHSA", value:"2016:0495");

  script_name(english:"RHEL 6 / 7 : nss-util (RHSA-2016:0495)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss-util packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.2, 6.4, and 6.5 Advanced
Update Support, and Red Hat Enterprise Linux 6.6 and 7.1 Extended
Update Support.

Red Hat Product Security has rated this update as having Critical
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. The nss-util package provides a set of utilities
for NSS and the Softoken module.

A heap-based buffer overflow flaw was found in the way NSS parsed
certain ASN.1 structures. An attacker could use this flaw to create a
specially crafted certificate which, when parsed by NSS, could cause
it to crash, or execute arbitrary code, using the permissions of the
user running an application compiled against the NSS library.
(CVE-2016-1950)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Francis Gabriel as the original reporter.

All nss-util users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. For the update
to take effect, all applications linked to the nss and nss-util
libraries must be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-36"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0495.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected nss-util, nss-util-debuginfo and / or
nss-util-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

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
if (! ereg(pattern:"^(6\.2|6\.4|6\.5|6\.6|7\.1)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.2 / 6.4 / 6.5 / 6.6 / 7.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0495";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"nss-util-3.19.1-3.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-util-3.14.3-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-util-3.13.1-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"nss-util-3.16.1-4.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"nss-util-3.14.3-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-util-3.13.1-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"nss-util-3.16.1-4.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"nss-util-debuginfo-3.19.1-3.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-util-debuginfo-3.14.3-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-util-debuginfo-3.13.1-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"nss-util-debuginfo-3.16.1-4.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"nss-util-debuginfo-3.14.3-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-util-debuginfo-3.13.1-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"nss-util-debuginfo-3.16.1-4.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"nss-util-devel-3.19.1-3.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-util-devel-3.14.3-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-util-devel-3.13.1-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"nss-util-devel-3.16.1-4.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"nss-util-devel-3.14.3-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-util-devel-3.13.1-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"nss-util-devel-3.16.1-4.el6_5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"1", reference:"nss-util-3.19.1-5.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"nss-util-debuginfo-3.19.1-5.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"nss-util-devel-3.19.1-5.el7_1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss-util / nss-util-debuginfo / nss-util-devel");
  }
}
