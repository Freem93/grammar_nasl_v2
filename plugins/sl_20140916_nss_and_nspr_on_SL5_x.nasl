#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77955);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/29 10:45:59 $");

  script_cve_id("CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1545");

  script_name(english:"Scientific Linux Security Update : nss and nspr on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way TLS False Start was implemented in NSS. An
attacker could use this flaw to potentially return unencrypted
information from the server. (CVE-2013-1740)

A race condition was found in the way NSS implemented session ticket
handling as specified by RFC 5077. An attacker could use this flaw to
crash an application using NSS or, in rare cases, execute arbitrary
code with the privileges of the user running that application.
(CVE-2014-1490)

It was found that NSS accepted weak Diffie-Hellman Key exchange (DHKE)
parameters. This could possibly lead to weak encryption being used in
communication between the client and the server. (CVE-2014-1491)

An out-of-bounds write flaw was found in NSPR. A remote attacker could
potentially use this flaw to crash an application using NSPR or,
possibly, execute arbitrary code with the privileges of the user
running that application. This NSPR flaw was not exposed to web
content in any shipped version of Firefox. (CVE-2014-1545)

It was found that the implementation of Internationalizing Domain
Names in Applications (IDNA) hostname matching in NSS did not follow
the RFC 6125 recommendations. This could lead to certain invalid
certificates with international characters to be accepted as valid.
(CVE-2014-1492)

The nss and nspr packages have been upgraded to upstream version
3.16.1 and 4.10.6 respectively, which provide a number of bug fixes
and enhancements over the previous versions.

This update also fixes the following bugs :

  - Previously, when the output.log file was not present on
    the system, the shell in the Network Security Services
    (NSS) specification handled test failures incorrectly as
    false positive test results. Consequently, certain
    utilities, such as 'grep', could not handle failures
    properly. This update improves error detection in the
    specification file, and 'grep' and other utilities now
    handle missing files or crashes as intended.

  - Prior to this update, a subordinate Certificate
    Authority (CA) of the ANSSI agency incorrectly issued an
    intermediate certificate installed on a network
    monitoring device. As a consequence, the monitoring
    device was enabled to act as an MITM (Man in the Middle)
    proxy performing traffic management of domain names or
    IP addresses that the certificate holder did not own or
    control. The trust in the intermediate certificate to
    issue the certificate for an MITM device has been
    revoked, and such a device can no longer be used for
    MITM attacks.

  - Due to a regression, MD5 certificates were rejected by
    default because Network Security Services (NSS) did not
    trust MD5 certificates. With this update, MD5
    certificates are supported in Scientific Linux 5."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1409&L=scientific-linux-errata&T=0&P=2118
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efdd4387"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"nss-3.16.1-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.16.1-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.16.1-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.16.1-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.16.1-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
