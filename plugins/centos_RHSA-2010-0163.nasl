#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0163 and 
# CentOS Errata and Security Advisory 2010:0163 respectively.
#

include("compat.inc");

if (description)
{
  script_id(45346);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2009-0590", "CVE-2009-2409", "CVE-2009-3555");
  script_bugtraq_id(34256);
  script_osvdb_id(59971);
  script_xref(name:"RHSA", value:"2010:0163");

  script_name(english:"CentOS 3 / 4 : openssl (CESA-2010:0163)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handled session
renegotiation. A man-in-the-middle attacker could use this flaw to
prefix arbitrary plain text to a client's session (for example, an
HTTPS connection to a website). This could force the server to process
an attacker's request as if authenticated using the victim's
credentials. This update addresses this flaw by implementing the TLS
Renegotiation Indication Extension, as defined in RFC 5746.
(CVE-2009-3555)

Refer to the following Knowledgebase article for additional details
about the CVE-2009-3555 flaw:
http://kbase.redhat.com/faq/docs/DOC-20491

Dan Kaminsky found that browsers could accept certificates with MD2
hash signatures, even though MD2 is no longer considered a
cryptographically strong algorithm. This could make it easier for an
attacker to create a malicious certificate that would be treated as
trusted by a browser. OpenSSL now disables the use of the MD2
algorithm inside signatures by default. (CVE-2009-2409)

An input validation flaw was found in the handling of the BMPString
and UniversalString ASN1 string types in OpenSSL's
ASN1_STRING_print_ex() function. An attacker could use this flaw to
create a specially crafted X.509 certificate that could cause
applications using the affected function to crash when printing
certificate contents. (CVE-2009-0590)

Note: The affected function is rarely used. No application shipped
with Red Hat Enterprise Linux calls this function, for example.

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016580.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a9c2b91"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e65cb52"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016609.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8058f05b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016610.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?200f2dae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/26");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openssl-0.9.7a-33.26")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openssl-0.9.7a-33.26")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openssl-devel-0.9.7a-33.26")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openssl-devel-0.9.7a-33.26")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openssl-perl-0.9.7a-33.26")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openssl-perl-0.9.7a-33.26")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-0.9.7a-43.17.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-0.9.7a-43.17.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-devel-0.9.7a-43.17.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-devel-0.9.7a-43.17.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-perl-0.9.7a-43.17.el4_8.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-perl-0.9.7a-43.17.el4_8.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
