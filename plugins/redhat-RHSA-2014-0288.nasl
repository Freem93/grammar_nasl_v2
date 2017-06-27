#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0288. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79001);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/06 15:40:56 $");

  script_cve_id("CVE-2014-0092");
  script_bugtraq_id(65919);
  script_osvdb_id(103933);
  script_xref(name:"RHSA", value:"2014:0288");

  script_name(english:"RHEL 5 / 6 : gnutls (RHSA-2014:0288)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 Extended Life Cycle Support, Red Hat
Enterprise Linux 5.3, 5.6 and 6.2 Long Life, and Red Hat Enterprise
Linux 5.9, 6.3 and 6.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

It was discovered that GnuTLS did not correctly handle certain errors
that could occur during the verification of an X.509 certificate,
causing it to incorrectly report a successful verification. An
attacker could use this flaw to create a specially crafted certificate
that could be accepted by GnuTLS as valid for a site chosen by the
attacker. (CVE-2014-0092)

This issue was discovered by Nikos Mavrogiannopoulos of the Red Hat
Security Technologies Team.

Users of GnuTLS are advised to upgrade to these updated packages,
which correct this issue. For the update to take effect, all
applications linked to the GnuTLS library must be restarted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0288.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
if (! ereg(pattern:"^(5\.3|5\.6|5\.9|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.3 / 5.6 / 5.9 / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0288";
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
  if (rpm_check(release:"RHEL5", sp:"9", reference:"gnutls-1.4.1-10.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"gnutls-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"gnutls-1.4.1-3.el5_3.6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"gnutls-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"gnutls-1.4.1-3.el5_3.6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"gnutls-debuginfo-1.4.1-10.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"gnutls-debuginfo-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"gnutls-debuginfo-1.4.1-3.el5_3.6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"gnutls-debuginfo-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"gnutls-debuginfo-1.4.1-3.el5_3.6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"gnutls-devel-1.4.1-10.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"gnutls-devel-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"gnutls-devel-1.4.1-3.el5_3.6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"gnutls-devel-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"gnutls-devel-1.4.1-3.el5_3.6")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"gnutls-utils-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"gnutls-utils-1.4.1-3.el5_3.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"gnutls-utils-1.4.1-10.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"gnutls-utils-1.4.1-10.el5_9.3")) flag++;

  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"gnutls-utils-1.4.1-7.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"gnutls-utils-1.4.1-3.el5_3.6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"gnutls-utils-1.4.1-10.el5_9.3")) flag++;


  if (rpm_check(release:"RHEL6", sp:"4", reference:"gnutls-2.8.5-10.el6_4.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"gnutls-2.8.5-7.el6_3.2")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"gnutls-2.8.5-4.el6_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gnutls-2.8.5-10.el6_4.3")) flag++; }

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"gnutls-2.8.5-4.el6_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gnutls-2.8.5-10.el6_4.3")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", reference:"gnutls-debuginfo-2.8.5-10.el6_4.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"gnutls-debuginfo-2.8.5-7.el6_3.2")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"gnutls-debuginfo-2.8.5-4.el6_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gnutls-debuginfo-2.8.5-10.el6_4.3")) flag++; }

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"gnutls-debuginfo-2.8.5-4.el6_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gnutls-debuginfo-2.8.5-10.el6_4.3")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", reference:"gnutls-devel-2.8.5-10.el6_4.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"gnutls-devel-2.8.5-7.el6_3.2")) flag++;

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"gnutls-devel-2.8.5-4.el6_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gnutls-devel-2.8.5-10.el6_4.3")) flag++; }

if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"gnutls-devel-2.8.5-4.el6_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gnutls-devel-2.8.5-10.el6_4.3")) flag++; }

  if (rpm_check(release:"RHEL6", sp:"4", reference:"gnutls-guile-2.8.5-10.el6_4.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"gnutls-guile-2.8.5-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"gnutls-guile-2.8.5-4.el6_2.3")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"gnutls-guile-2.8.5-4.el6_2.3")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"gnutls-utils-2.8.5-10.el6_4.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"gnutls-utils-2.8.5-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"gnutls-utils-2.8.5-10.el6_4.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"gnutls-utils-2.8.5-7.el6_3.2")) flag++;

if (sp == "3") {   if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"gnutls-utils-2.8.5-7.el6_3.2")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"gnutls-utils-2.8.5-4.el6_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gnutls-utils-2.8.5-10.el6_4.3")) flag++; }


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-debuginfo / gnutls-devel / gnutls-guile / etc");
  }
}
