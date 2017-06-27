#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0518. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58869);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2012-2110");
  script_bugtraq_id(53158);
  script_osvdb_id(81223);
  script_xref(name:"RHSA", value:"2012:0518");

  script_name(english:"RHEL 5 / 6 : openssl (RHSA-2012:0518)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl, openssl097a, and openssl098e packages that fix one
security issue are now available for Red Hat Enterprise Linux 5 and 6.

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
    value:"http://rhn.redhat.com/errata/RHSA-2012-0518.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl097a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl098e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl098e-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0518";
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
{
  flag = 0;
  if (rpm_check(release:"RHEL5", reference:"openssl-0.9.8e-22.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openssl-devel-0.9.8e-22.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssl-perl-0.9.8e-22.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssl-perl-0.9.8e-22.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssl-perl-0.9.8e-22.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openssl097a-0.9.7a-11.el5_8.2")) flag++;


  if (rpm_check(release:"RHEL6", reference:"openssl-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-debuginfo-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-devel-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-perl-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-perl-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-perl-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-static-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-static-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-static-1.0.0-20.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl098e-0.9.8e-17.el6_2.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl098e-debuginfo-0.9.8e-17.el6_2.2")) flag++;


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
