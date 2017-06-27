#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:063. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12368);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2003-0078");
  script_xref(name:"RHSA", value:"2003:063");

  script_name(english:"RHEL 2.1 : openssl (RHSA-2003:063)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages are available that fix a potential
timing-based attack.

[Updated 12 March 2003] Added packages for Red Hat Enterprise Linux ES
and Red Hat Enterprise Linux WS

OpenSSL is a commercial-grade, full-featured, open source toolkit
which implements the Secure Sockets Layer (SSL v2/v3) and Transport
Layer Security (TLS v1) protocols as well as a full-strength, general
purpose cryptography library.

In a paper, Brice Canvel, Alain Hiltgen, Serge Vaudenay, and Martin
Vuagnoux describe and demonstrate a timing-based attack on CBC
ciphersuites in SSL and TLS. An active attacker may be able to use
timing observations to distinguish between two different error cases:
cipher padding errors and MAC verification errors. Over multiple
connections this can leak sufficient information to be able to
retrieve the plaintext of a common, fixed block.

In order for an attack to be sucessful an attacker must be able to act
as a man-in-the-middle to intercept and modify multiple connections
which all involve a common fixed plaintext block (such as a password),
and have good network conditions that allow small changes in timing to
be reliably observed.

These updated packages contain a patch provided by the OpenSSL group
that corrects this vulnerability.

Because server applications are affected by these vulnerabilities, we
advise users to restart all services that use OpenSSL functionality or
alternatively reboot their systems after installing these updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lasecwww.epfl.ch/pub/lasec/doc/Vau02a.ps"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-063.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl095a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/20");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2003:063";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-0.9.6b-30.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"openssl-0.9.6b-30.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-devel-0.9.6b-30.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-perl-0.9.6b-30.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl095a-0.9.5a-18.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl096-0.9.6-13.7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl095a / openssl096");
  }
}
