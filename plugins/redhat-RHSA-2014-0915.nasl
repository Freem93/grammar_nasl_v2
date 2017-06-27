#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0915. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79110);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-1544");
  script_osvdb_id(109430);
  script_xref(name:"RHSA", value:"2014:0915");

  script_name(english:"RHEL 5 / 6 : nss (RHSA-2014:0915)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix one security issue are now available for
Red Hat Enterprise Linux 5.6 Long Life, Red Hat Enterprise Linux 5.9
Extended Update Support, Red Hat Enterprise Linux 6.2 Advanced Update
Support, and Red Hat Enterprise Linux 6.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
Critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

A race condition was found in the way NSS verified certain
certificates. A remote attacker could use this flaw to crash an
application using NSS or, possibly, execute arbitrary code with the
privileges of the user running that application. (CVE-2014-1544)

Red Hat would like to thank the Mozilla project for reporting
CVE-2014-1544. Upstream acknowledges Tyson Smith and Jesse
Schwartzentruber as the original reporters.

Users of NSS are advised to upgrade to these updated packages, which
correct this issue. After installing this update, applications using
NSS must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0915.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.6|5\.9|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.6 / 5.9 / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0915";
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
  if (rpm_check(release:"RHEL5", sp:"9", reference:"nss-3.14.3-9.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"nss-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"nss-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"nss-debuginfo-3.14.3-9.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"nss-debuginfo-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"nss-debuginfo-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"nss-devel-3.14.3-9.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"nss-devel-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"nss-devel-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"nss-pkcs11-devel-3.14.3-9.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"nss-pkcs11-devel-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"nss-pkcs11-devel-3.12.8-9.el5_6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"nss-tools-3.12.8-9.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"nss-tools-3.14.3-9.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"nss-tools-3.14.3-9.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"nss-tools-3.12.8-9.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"nss-tools-3.14.3-9.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", sp:"4", reference:"nss-3.14.3-6.el6_4")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-3.14.3-6.el6_4")) flag++; }

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-3.14.3-6.el6_4")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", reference:"nss-debuginfo-3.14.3-6.el6_4")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-debuginfo-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-debuginfo-3.14.3-6.el6_4")) flag++; }

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-debuginfo-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-debuginfo-3.14.3-6.el6_4")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", reference:"nss-devel-3.14.3-6.el6_4")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-devel-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-devel-3.14.3-6.el6_4")) flag++; }

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-devel-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-devel-3.14.3-6.el6_4")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", reference:"nss-pkcs11-devel-3.14.3-6.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"nss-pkcs11-devel-3.13.1-10.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-pkcs11-devel-3.13.1-10.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-sysinit-3.14.3-6.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"nss-sysinit-3.14.3-6.el6_4")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-sysinit-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-sysinit-3.14.3-6.el6_4")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"nss-tools-3.14.3-6.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"nss-tools-3.14.3-6.el6_4")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"nss-tools-3.13.1-10.el6_2")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-tools-3.14.3-6.el6_4")) flag++; }


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-sysinit / etc");
  }
}
