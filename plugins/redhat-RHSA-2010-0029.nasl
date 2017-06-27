#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0029. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43868);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/04 15:51:46 $");

  script_cve_id("CVE-2009-4212");
  script_bugtraq_id(37749);
  script_xref(name:"RHSA", value:"2010:0029");

  script_name(english:"RHEL 3 / 4 / 5 : krb5 (RHSA-2010:0029)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5, and Red Hat
Enterprise Linux 4.7, 5.2, and 5.3 Extended Update Support.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third party, the Key Distribution Center (KDC).

Multiple integer underflow flaws, leading to heap-based corruption,
were found in the way the MIT Kerberos Key Distribution Center (KDC)
decrypted ciphertexts encrypted with the Advanced Encryption Standard
(AES) and ARCFOUR (RC4) encryption algorithms. If a remote KDC client
were able to provide a specially crafted AES- or RC4-encrypted
ciphertext or texts, it could potentially lead to either a denial of
service of the central KDC (KDC crash or abort upon processing the
crafted ciphertext), or arbitrary code execution with the privileges
of the KDC (i.e., root privileges). (CVE-2009-4212)

All krb5 users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running services using
the MIT Kerberos libraries must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2009-004.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0029.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0029";
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
  if (rpm_check(release:"RHEL3", reference:"krb5-devel-1.2.7-71")) flag++;

  if (rpm_check(release:"RHEL3", reference:"krb5-libs-1.2.7-71")) flag++;

  if (rpm_check(release:"RHEL3", reference:"krb5-server-1.2.7-71")) flag++;

  if (rpm_check(release:"RHEL3", reference:"krb5-workstation-1.2.7-71")) flag++;


if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"krb5-devel-1.3.4-60.el4_7.3")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"krb5-devel-1.3.4-62.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"krb5-libs-1.3.4-60.el4_7.3")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"krb5-libs-1.3.4-62.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"krb5-server-1.3.4-60.el4_7.3")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"krb5-server-1.3.4-62.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"krb5-workstation-1.3.4-60.el4_7.3")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"krb5-workstation-1.3.4-62.el4_8.1")) flag++; }


if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", reference:"krb5-devel-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", reference:"krb5-devel-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"krb5-devel-1.6.1-36.el5_4.1")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", reference:"krb5-libs-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", reference:"krb5-libs-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"krb5-libs-1.6.1-36.el5_4.1")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"krb5-server-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", cpu:"i386", reference:"krb5-server-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-server-1.6.1-36.el5_4.1")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"krb5-server-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"krb5-server-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-server-1.6.1-36.el5_4.1")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"krb5-server-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"krb5-server-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-server-1.6.1-36.el5_4.1")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"krb5-workstation-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", cpu:"i386", reference:"krb5-workstation-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"krb5-workstation-1.6.1-36.el5_4.1")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"krb5-workstation-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"krb5-workstation-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"krb5-workstation-1.6.1-36.el5_4.1")) flag++; }

if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"krb5-workstation-1.6.1-31.el5_3.4")) flag++; }
else if (sp == "2") {   if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"krb5-workstation-1.6.1-25.el5_2.3")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"krb5-workstation-1.6.1-36.el5_4.1")) flag++; }


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
  }
}
