#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0372 and 
# CentOS Errata and Security Advisory 2016:0372 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(89762);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0800");
  script_osvdb_id(119757, 133715, 135149, 135152, 135153);
  script_xref(name:"RHSA", value:"2016:0372");

  script_name(english:"CentOS 6 / 7 : openssl098e (CESA-2016:0372) (DROWN)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl098e packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A padding oracle flaw was found in the Secure Sockets Layer version
2.0 (SSLv2) protocol. An attacker can potentially use this flaw to
decrypt RSA-encrypted cipher text from a connection using a newer
SSL/TLS protocol version, allowing them to decrypt such connections.
This cross-protocol attack is publicly referred to as DROWN.
(CVE-2016-0800)

Note: This issue was addressed by disabling the SSLv2 protocol by
default when using the 'SSLv23' connection methods, and removing
support for weak SSLv2 cipher suites. For more information, refer to
the knowledge base article linked to in the References section.

It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2
connection handshakes that indicated non-zero clear key length for
non-export cipher suites. An attacker could use this flaw to decrypt
recorded SSLv2 sessions with the server by using it as a decryption
oracle.(CVE-2016-0703)

It was discovered that the SSLv2 protocol implementation in OpenSSL
did not properly implement the Bleichenbacher protection for export
cipher suites. An attacker could use a SSLv2 server using OpenSSL as a
Bleichenbacher oracle. (CVE-2016-0704)

Note: The CVE-2016-0703 and CVE-2016-0704 issues could allow for more
efficient exploitation of the CVE-2016-0800 issue via the DROWN
attack.

A denial of service flaw was found in the way OpenSSL handled SSLv2
handshake messages. A remote attacker could use this flaw to cause a
TLS/SSL server using OpenSSL to exit on a failed assertion if it had
both the SSLv2 protocol and EXPORT-grade cipher suites enabled.
(CVE-2015-0293)

A flaw was found in the way malicious SSLv2 clients could negotiate
SSLv2 ciphers that have been disabled on the server. This could result
in weak SSLv2 ciphers being used for SSLv2 connections, making them
vulnerable to man-in-the-middle attacks. (CVE-2015-3197)

Red Hat would like to thank the OpenSSL project for reporting these
issues. Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as
the original reporters of CVE-2016-0800 and CVE-2015-3197; David
Adrian (University of Michigan) and J. Alex Halderman (University of
Michigan) as the original reporters of CVE-2016-0703 and
CVE-2016-0704; and Sean Burford (Google) and Emilia Kasper (OpenSSL
development team) as the original reporters of CVE-2015-0293.

All openssl098e users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
For the update to take effect, all services linked to the openssl098e
library must be restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-March/021719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8f66304"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-March/021720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f6a487d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl098e package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl098e");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"openssl098e-0.9.8e-20.el6.centos.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl098e-0.9.8e-29.el7.centos.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
