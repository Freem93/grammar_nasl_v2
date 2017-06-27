#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0680 and 
# CentOS Errata and Security Advisory 2006:0680 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22427);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-4790");
  script_bugtraq_id(20027);
  script_osvdb_id(28778);
  script_xref(name:"RHSA", value:"2006:0680");

  script_name(english:"CentOS 4 : gnutls (CESA-2006:0680)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix a security issue are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The GnuTLS Library provides support for cryptographic algorithms and
protocols such as TLS. GnuTLS includes libtasn1, a library developed
for ASN.1 structures management that includes DER encoding and
decoding.

Daniel Bleichenbacher recently described an attack on PKCS #1 v1.5
signatures. Where an RSA key with exponent 3 is used it may be
possible for an attacker to forge a PKCS #1 v1.5 signature that would
be incorrectly verified by implementations that do not check for
excess data in the RSA exponentiation result of the signature.

The core GnuTLS team discovered that GnuTLS is vulnerable to a variant
of the Bleichenbacker attack. This issue affects applications that use
GnuTLS to verify X.509 certificates as well as other uses of PKCS #1
v1.5. (CVE-2006-4790)

In Red Hat Enterprise Linux 4, the GnuTLS library is only used by the
Evolution client when connecting to an Exchange server or when
publishing calendar information to a WebDAV server.

Users are advised to upgrade to these updated packages, which contain
a backported patch from the GnuTLS maintainers to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013275.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1a59365"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013276.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?846b06f6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnutls-1.0.20-3.2.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnutls-1.0.20-3.2.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnutls-devel-1.0.20-3.2.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnutls-devel-1.0.20-3.2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
