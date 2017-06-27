#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:293. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12425);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2003-0543", "CVE-2003-0544");
  script_bugtraq_id(8732);
  script_osvdb_id(3686);
  script_xref(name:"RHSA", value:"2003:293");

  script_name(english:"RHEL 2.1 : openssl (RHSA-2003:293)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages are available that fix ASN.1 parsing
vulnerabilities.

OpenSSL is a commercial-grade, full-featured, and open source toolkit
that implements Secure Sockets Layer (SSL v2/v3) and Transport Layer
Security (TLS v1) protocols as well as a full-strength general purpose
cryptography library.

NISCC testing of implementations of the SSL protocol uncovered two
bugs in OpenSSL 0.9.6. The parsing of unusual ASN.1 tag values can
cause OpenSSL to crash. A remote attacker could trigger this bug by
sending a carefully crafted SSL client certificate to an application.
The effects of such an attack vary depending on the application
targetted; against Apache the effects are limited, as the attack would
only cause child processes to die and be replaced. An attack against
other applications that use OpenSSL could result in a Denial of
Service. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the names CVE-2003-0543 and CVE-2003-0544
to this issue.

These erratum packages contain a patch provided by the OpenSSL group
that protects against this issue.

Because server applications are affected by this issue, users are
advised to either restart all services that use OpenSSL functionality
or reboot their systems after installing these updates.

Red Hat would like to thank NISCC and Stephen Henson for their work on
this vulnerability.

These packages also include a patch from OpenSSL 0.9.6f which removes
the calls to abort the process in certain circumstances. Red Hat would
like to thank Patrik Hornik for notifying us of this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0543.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0544.html"
  );
  # http://www.niscc.gov.uk/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cpni.gov.uk/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20030930.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-293.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl095a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/14");
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
  rhsa = "RHSA-2003:293";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-0.9.6b-35.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"openssl-0.9.6b-35.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-devel-0.9.6b-35.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-perl-0.9.6b-35.7")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl095a-0.9.5a-23.7.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl096-0.9.6-23.7")) flag++;

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
