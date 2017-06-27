#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0964 and 
# CentOS Errata and Security Advisory 2007:0964 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43658);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/03/19 14:21:01 $");

  script_cve_id("CVE-2007-3108", "CVE-2007-4995", "CVE-2007-5135");
  script_bugtraq_id(25831);
  script_osvdb_id(29262, 37055, 37895);
  script_xref(name:"RHSA", value:"2007:0964");

  script_name(english:"CentOS 5 : openssl (CESA-2007:0964)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that correct several security issues are now
available for Red Hat Enterprise 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength general purpose cryptography library. Datagram TLS
(DTLS) is a protocol based on TLS that is capable of securing datagram
transport (UDP for instance).

The OpenSSL security team discovered a flaw in DTLS support. An
attacker could create a malicious client or server that could trigger
a heap overflow. This is possibly exploitable to run arbitrary code,
but it has not been verified (CVE-2007-4995). Note that this flaw only
affects applications making use of DTLS. Red Hat does not ship any
DTLS client or server applications in Red Hat Enterprise Linux.

A flaw was found in the SSL_get_shared_ciphers() utility function. An
attacker could send a list of ciphers to an application that used this
function and overrun a buffer with a single byte (CVE-2007-5135). Few
applications make use of this vulnerable function and generally it is
used only when applications are compiled for debugging.

A number of possible side-channel attacks were discovered affecting
OpenSSL. A local attacker could possibly obtain RSA private keys being
used on a system. In practice these attacks would be difficult to
perform outside of a lab environment. This update contains backported
patches designed to mitigate these issues. (CVE-2007-3108).

Users of OpenSSL should upgrade to these updated packages, which
contain backported patches to resolve these issues.

Please note that the fix for the DTLS flaw involved an overhaul of the
DTLS handshake processing which may introduce incompatibilities if a
new client is used with an older server.

After installing this update, users are advised to either restart all
services that use OpenSSL or restart their system."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014303.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f84701e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014304.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6197ba27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8b-8.3.el5_0.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8b-8.3.el5_0.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8b-8.3.el5_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
