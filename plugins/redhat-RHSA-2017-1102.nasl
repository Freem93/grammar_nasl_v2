#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1102. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99503);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5461");
  script_osvdb_id(155952);
  script_xref(name:"RHSA", value:"2017:1102");

  script_name(english:"RHEL 6 / 7 : nss-util (RHSA-2017:1102)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nss-util is now available for Red Hat Enterprise Linux
6.2 Advanced Update Support, Red Hat Enterprise Linux 6.4 Advanced
Update Support, Red Hat Enterprise Linux 6.5 Advanced Update Support,
Red Hat Enterprise Linux 6.5 Telco Extended Update Support, Red Hat
Enterprise Linux 6.6 Advanced Update Support, Red Hat Enterprise Linux
6.6 Telco Extended Update Support, Red Hat Enterprise Linux 6.7
Extended Update Support, and Red Hat Enterprise Linux 7.2 Extended
Update Support.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

Security Fix(es) :

* An out-of-bounds write flaw was found in the way NSS performed
certain Base64-decoding operations. An attacker could use this flaw to
create a specially crafted certificate which, when parsed by NSS,
could cause it to crash or execute arbitrary code, using the
permissions of the user running an application compiled against the
NSS library. (CVE-2017-5461)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Ronald Crane as the original reporter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1102.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected nss-util, nss-util-debuginfo and / or
nss-util-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.2|6\.4|6\.5|6\.6|6\.7|7\.2)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.2 / 6.4 / 6.5 / 6.6 / 6.7 / 7.2", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1102";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL6", sp:"7", reference:"nss-util-3.21.4-1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"nss-util-3.19.1-4.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-util-3.14.3-9.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-util-3.13.1-11.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"nss-util-3.16.1-5.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"nss-util-3.19.1-4.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"nss-util-3.14.3-9.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-util-3.13.1-11.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"nss-util-3.16.1-5.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", reference:"nss-util-debuginfo-3.21.4-1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"nss-util-debuginfo-3.19.1-4.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-util-debuginfo-3.14.3-9.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-util-debuginfo-3.13.1-11.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"nss-util-debuginfo-3.16.1-5.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"nss-util-debuginfo-3.19.1-4.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"nss-util-debuginfo-3.14.3-9.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-util-debuginfo-3.13.1-11.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"nss-util-debuginfo-3.16.1-5.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", reference:"nss-util-devel-3.21.4-1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"nss-util-devel-3.19.1-4.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-util-devel-3.14.3-9.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-util-devel-3.13.1-11.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"nss-util-devel-3.16.1-5.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"nss-util-devel-3.19.1-4.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"nss-util-devel-3.14.3-9.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-util-devel-3.13.1-11.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"nss-util-devel-3.16.1-5.el6_5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"2", reference:"nss-util-3.21.4-1.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"nss-util-debuginfo-3.21.4-1.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"nss-util-devel-3.21.4-1.el7_2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss-util / nss-util-debuginfo / nss-util-devel");
  }
}
