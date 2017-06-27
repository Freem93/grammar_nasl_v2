#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0996 and 
# Oracle Linux Security Advisory ELSA-2016-0996 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91152);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2842");
  script_osvdb_id(135095, 135096, 137577, 137896, 137898, 137899, 137900);
  script_xref(name:"RHSA", value:"2016:0996");

  script_name(english:"Oracle Linux 6 : openssl (ELSA-2016-0996)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0996 :

An update for openssl is now available for Red Hat Enterprise Linux 6.

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
    value:"https://oss.oracle.com/pipermail/el-errata/2016-May/006053.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"openssl-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-devel-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-perl-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-static-1.0.1e-48.el6_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl-static");
}
