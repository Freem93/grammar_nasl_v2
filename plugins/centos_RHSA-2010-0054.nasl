#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0054 and 
# CentOS Errata and Security Advisory 2010:0054 respectively.
#

include("compat.inc");

if (description)
{
  script_id(44097);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 21:12:09 $");

  script_cve_id("CVE-2009-2409", "CVE-2009-4355");
  script_bugtraq_id(31692);
  script_xref(name:"RHSA", value:"2010:0054");

  script_name(english:"CentOS 5 : openssl (CESA-2010:0054)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was found that the OpenSSL library did not properly re-initialize
its internal state in the SSL_library_init() function after previous
calls to the CRYPTO_cleanup_all_ex_data() function, which would cause
a memory leak for each subsequent SSL connection. This flaw could
cause server applications that call those functions during reload,
such as a combination of the Apache HTTP Server, mod_ssl, PHP, and
cURL, to consume all available memory, resulting in a denial of
service. (CVE-2009-4355)

Dan Kaminsky found that browsers could accept certificates with MD2
hash signatures, even though MD2 is no longer considered a
cryptographically strong algorithm. This could make it easier for an
attacker to create a malicious certificate that would be treated as
trusted by a browser. OpenSSL now disables the use of the MD2
algorithm inside signatures by default. (CVE-2009-2409)

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9e59025"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016484.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24336a3a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/21");
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
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-12.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-12.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-12.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
