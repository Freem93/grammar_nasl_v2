#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1335 and 
# CentOS Errata and Security Advisory 2009:1335 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43785);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2006-7250", "CVE-2009-0590", "CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387");
  script_bugtraq_id(34256, 35001, 35138, 35174, 35417);
  script_xref(name:"RHSA", value:"2009:1335");

  script_name(english:"CentOS 5 : openssl (CESA-2009:1335)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix several security issues, various
bugs, and add enhancements are now available for Red Hat Enterprise
Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength general purpose cryptography library. Datagram TLS
(DTLS) is a protocol based on TLS that is capable of securing datagram
transport (for example, UDP).

Multiple denial of service flaws were discovered in OpenSSL's DTLS
implementation. A remote attacker could use these flaws to cause a
DTLS server to use excessive amounts of memory, or crash on an invalid
memory access or NULL pointer dereference. (CVE-2009-1377,
CVE-2009-1378, CVE-2009-1379, CVE-2009-1386, CVE-2009-1387)

Note: These flaws only affect applications that use DTLS. Red Hat does
not ship any DTLS client or server applications in Red Hat Enterprise
Linux.

An input validation flaw was found in the handling of the BMPString
and UniversalString ASN1 string types in OpenSSL's
ASN1_STRING_print_ex() function. An attacker could use this flaw to
create a specially crafted X.509 certificate that could cause
applications using the affected function to crash when printing
certificate contents. (CVE-2009-0590)

Note: The affected function is rarely used. No application shipped
with Red Hat Enterprise Linux calls this function, for example.

These updated packages also fix the following bugs :

* 'openssl smime -verify -in' verifies the signature of the input file
and the '-verify' switch expects a signed or encrypted input file.
Previously, running openssl on an S/MIME file that was not encrypted
or signed caused openssl to segfault. With this update, the input file
is now checked for a signature or encryption. Consequently, openssl
now returns an error and quits when attempting to verify an
unencrypted or unsigned S/MIME file. (BZ#472440)

* when generating RSA keys, pairwise tests were called even in
non-FIPS mode. This prevented small keys from being generated. With
this update, generating keys in non-FIPS mode no longer calls the
pairwise tests and keys as small as 32-bits can be generated in this
mode. Note: In FIPS mode, pairwise tests are still called and keys
generated in this mode must still be 1024-bits or larger. (BZ#479817)

As well, these updated packages add the following enhancements :

* both the libcrypto and libssl shared libraries, which are part of
the OpenSSL FIPS module, are now checked for integrity on
initialization of FIPS mode. (BZ#475798)

* an issuing Certificate Authority (CA) allows multiple certificate
templates to inherit the CA's Common Name (CN). Because this CN is
used as a unique identifier, each template had to have its own
Certificate Revocation List (CRL). With this update, multiple CRLs
with the same subject name can now be stored in a X509_STORE
structure, with their signature field being used to distinguish
between them. (BZ#457134)

* the fipscheck library is no longer needed for rebuilding the openssl
source RPM. (BZ#475798)

OpenSSL users should upgrade to these updated packages, which resolve
these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9af15d65"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eac0ac10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-12.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-12.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-12.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
