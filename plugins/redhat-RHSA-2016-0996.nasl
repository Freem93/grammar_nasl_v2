#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0996. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91037);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2842");
  script_osvdb_id(135095, 135096, 137577, 137896, 137898, 137899, 137900);
  script_xref(name:"RHSA", value:"2016:0996");

  script_name(english:"RHEL 6 : openssl (RHSA-2016:0996)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openssl is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL)
and Transport Layer Security (TLS) protocols, as well as a
full-strength general-purpose cryptography library.

Security Fix(es) :

* A flaw was found in the way OpenSSL encoded certain ASN.1 data
structures. An attacker could use this flaw to create a specially
crafted certificate which, when verified or re-encoded by OpenSSL,
could cause it to crash, or execute arbitrary code using the
permissions of the user running an application compiled against the
OpenSSL library. (CVE-2016-2108)

* Two integer overflow flaws, leading to buffer overflows, were found
in the way the EVP_EncodeUpdate() and EVP_EncryptUpdate() functions of
OpenSSL parsed very large amounts of input data. A remote attacker
could use these flaws to crash an application using OpenSSL or,
possibly, execute arbitrary code with the permissions of the user
running that application. (CVE-2016-2105, CVE-2016-2106)

* It was discovered that OpenSSL leaked timing information when
decrypting TLS/SSL and DTLS protocol encrypted records when the
connection used the AES CBC cipher suite and the server supported
AES-NI. A remote attacker could possibly use this flaw to retrieve
plain text from encrypted packets by using a TLS/SSL or DTLS server as
a padding oracle. (CVE-2016-2107)

* Several flaws were found in the way BIO_*printf functions were
implemented in OpenSSL. Applications which passed large amounts of
untrusted data through these functions could crash or potentially
execute code with the permissions of the user running such an
application. (CVE-2016-0799, CVE-2016-2842)

* A denial of service flaw was found in the way OpenSSL parsed certain
ASN.1-encoded data from BIO (OpenSSL's I/O abstraction) inputs. An
application using OpenSSL that accepts untrusted ASN.1 BIO input could
be forced to allocate an excessive amount of data. (CVE-2016-2109)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2016-2108, CVE-2016-2842, CVE-2016-2105, CVE-2016-2106,
CVE-2016-2107, and CVE-2016-0799. Upstream acknowledges Huzaifa
Sidhpurwala (Red Hat), Hanno Bock, and David Benjamin (Google) as the
original reporters of CVE-2016-2108; Guido Vranken as the original
reporter of CVE-2016-2842, CVE-2016-2105, CVE-2016-2106, and
CVE-2016-0799; and Juraj Somorovsky as the original reporter of
CVE-2016-2107."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2108.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0996.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/11");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0996";
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
  if (rpm_check(release:"RHEL6", reference:"openssl-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openssl-debuginfo-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openssl-devel-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-perl-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-perl-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-perl-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-static-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-static-1.0.1e-48.el6_8.1")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-static-1.0.1e-48.el6_8.1")) flag++;

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
