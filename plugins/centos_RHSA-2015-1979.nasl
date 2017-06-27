#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1979 and 
# CentOS Errata and Security Advisory 2015:1979 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(86711);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 18:15:06 $");

  script_cve_id("CVE-2015-3240");
  script_osvdb_id(126615);
  script_xref(name:"RHSA", value:"2015:1979");

  script_name(english:"CentOS 7 : libreswan (CESA-2015:1979)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libreswan packages that fix one security issue, several bugs,
and add several enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Libreswan is an implementation of IPsec & IKE for Linux. IPsec is the
Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services. These services allow you
to build secure tunnels through untrusted networks such as virtual
private network (VPN).

A flaw was discovered in the way Libreswan's IKE daemon processed IKE
KE payloads. A remote attacker could send specially crafted IKE
payload with a KE payload of g^x=0 that, when processed, would lead to
a denial of service (daemon crash). (CVE-2015-3240)

This issue was discovered by Paul Wouters of Red Hat.

Note: Please note that when upgrading from an earlier version of
Libreswan, the existing CA certificates in the /etc/ipsec.d/cacerts/
directory and the existing certificate revocation list (CRL) files
from the /etc/ipsec.d/crls/ directory are automatically imported into
the NSS database. Once completed, these directories are no longer used
by Libreswan. To install new CA certificates or new CRLS, the certutil
and crlutil commands must be used to import these directly into the
Network Security Services (NSS) database.

This update also adds the following enhancements :

* This update adds support for RFC 7383 IKEv2 Fragmentation, RFC 7619
Auth Null and ID Null, INVALID_KE renegotiation, CRL and OCSP support
via NSS, AES_CTR and AES_GCM support for IKEv2, CAVS testing for FIPS
compliance.

In addition, this update enforces FIPS algorithms restrictions in FIPS
mode, and runs Composite Application Validation System (CAVS) testing
for FIPS compliance during package build. A new Cryptographic
Algorithm Validation Program (CAVP) binary can be used to re-run the
CAVS tests at any time. Regardless of FIPS mode, the pluto daemon runs
RFC test vectors for various algorithms.

Furthermore, compiling on all architectures now enables the '-Werror'
GCC option, which enhances the security by making all warnings into
errors. (BZ#1263346)

* This update also fixes several memory leaks and introduces a
sub-second packet retransmit option. (BZ#1268773)

* This update improves migration support from Openswan to Libreswan.
Specifically, all Openswan options that can take a time value without
a suffix are now supported, and several new keywords for use in the
/etc/ipsec.conf file have been introduced. See the relevant man pages
for details. (BZ#1268775)

* With this update, loopback support via the 'loopback=' option has
been deprecated. (BZ#1270673)

All Libreswan users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-November/021462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16e84911"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreswan package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreswan-3.15-5.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
