#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0522. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64033);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2012-2110");
  script_bugtraq_id(53158);
  script_xref(name:"RHSA", value:"2012:0522");

  script_name(english:"RHEL 5 / 6 : openssl (RHSA-2012:0522)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix one security issue are now available
for Red Hat Enterprise Linux 3 and 4 Extended Life Cycle Support; Red
Hat Enterprise Linux 5.3 Long Life; and Red Hat Enterprise Linux 5.6,
6.0 and 6.1 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

Multiple numeric conversion errors, leading to a buffer overflow, were
found in the way OpenSSL parsed ASN.1 (Abstract Syntax Notation One)
data from BIO (OpenSSL's I/O abstraction) inputs. Specially crafted
DER (Distinguished Encoding Rules) encoded data read from a file or
other BIO input could cause an application using the OpenSSL library
to crash or, potentially, execute arbitrary code. (CVE-2012-2110)

All OpenSSL users should upgrade to these updated packages, which
contain a backported patch to resolve this issue. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20120419.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0522.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.3|5\.6|6\.0|6\.1)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.3 / 5.6 / 6.0 / 6.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0522";
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
  if (rpm_check(release:"RHEL5", sp:"6", reference:"openssl-0.9.8e-12.el5_6.9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"openssl-0.9.8e-7.el5_3.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"openssl-0.9.8e-7.el5_3.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"openssl-0.9.8e-7.el5_3.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", reference:"openssl-devel-0.9.8e-12.el5_6.9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"openssl-devel-0.9.8e-7.el5_3.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"openssl-devel-0.9.8e-7.el5_3.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"openssl-perl-0.9.8e-12.el5_6.9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"openssl-perl-0.9.8e-7.el5_3.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"openssl-perl-0.9.8e-12.el5_6.9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"openssl-perl-0.9.8e-12.el5_6.9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"openssl-perl-0.9.8e-7.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"1", reference:"openssl-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", reference:"openssl-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", reference:"openssl-debuginfo-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", reference:"openssl-debuginfo-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", reference:"openssl-devel-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", reference:"openssl-devel-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"openssl-perl-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"openssl-perl-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"openssl-perl-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"openssl-perl-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"openssl-perl-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"openssl-perl-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"openssl-static-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"openssl-static-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"openssl-static-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"openssl-static-1.0.0-4.el6_0.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"openssl-static-1.0.0-10.el6_1.6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"openssl-static-1.0.0-4.el6_0.3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
  }
}
