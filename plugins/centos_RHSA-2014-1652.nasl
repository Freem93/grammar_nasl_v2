#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1652 and 
# CentOS Errata and Security Advisory 2014:1652 respectively.
#

include("compat.inc");

if (description)
{
  script_id(78516);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567");
  script_bugtraq_id(70574, 70584, 70586);
  script_osvdb_id(113251, 113373, 113374);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"RHSA", value:"2014:1652");

  script_name(english:"CentOS 6 / 7 : openssl (CESA-2014:1652)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that contain a backported patch to mitigate
the CVE-2014-3566 issue known as SSLv3 Padding Oracle On Downgraded
Legacy Encryption Vulnerability (POODLE), and fixed two security
issues that are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL),
Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose
cryptography library.

This update adds support for the TLS Fallback Signaling Cipher Suite
Value (TLS_FALLBACK_SCSV), which can be used to prevent protocol
downgrade attacks against applications which re-connect using a lower
SSL/TLS protocol version when the initial connection indicating the
highest supported protocol version fails.

This can prevent a forceful downgrade of the communication to SSL 3.0.
The SSL 3.0 protocol was found to be vulnerable to the padding oracle
attack when using block cipher suites in cipher block chaining (CBC)
mode. This issue is identified as CVE-2014-3566 and also known under
the alias POODLE. This SSL 3.0 protocol flaw will not be addressed in
a future update; it is recommended that users configure their
applications to require at least TLS protocol version 1.0 for secure
communication.

For additional information about this flaw, see the Knowledgebase
article at https://access.redhat.com/articles/1232123

A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure
Real-time Transport Protocol (SRTP) extension data. A remote attacker
could send multiple specially crafted handshake messages to exhaust
all available memory of an SSL/TLS or DTLS server. (CVE-2014-3513)

A memory leak flaw was found in the way an OpenSSL handled failed
session ticket integrity checks. A remote attacker could exhaust all
available memory of an SSL/TLS or DTLS server by sending a large
number of invalid session tickets to that server. (CVE-2014-3567)

All OpenSSL users are advised to upgrade to these updated packages,
which contain backported patches to mitigate the CVE-2014-3566 issue
and correct the CVE-2014-3513 and CVE-2014-3567 issues. For the update
to take effect, all services linked to the OpenSSL library (such as
httpd and other SSL-enabled services) must be restarted or the system
rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-October/020695.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5a8460d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-October/020697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b0ea329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.imperialviolet.org/2014/10/14/poodle.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/~bodo/ssl-poodle.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

packages = make_list("openssl", "openssl-devel", "openssl-perl", "openssl-static");
advisory_version = "1.0.1e-30.el6_5.2";
buggy_branch = "1.0.1e-30.el6\.([89]|\d{2,})\|";
foreach currpackage (packages)
{
  rpm_regex = currpackage + "-" + buggy_branch;
  advisory_reference = currpackage + "-" + advisory_version;
  if (! rpm_exists(release:"CentOS-6", rpm:rpm_regex) && rpm_check(release:"CentOS-6", reference:advisory_reference)) flag++;
}

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-1.0.1e-34.el7_0.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-34.el7_0.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-34.el7_0.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-34.el7_0.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-static-1.0.1e-34.el7_0.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
