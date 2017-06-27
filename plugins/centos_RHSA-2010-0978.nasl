#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0978 and 
# CentOS Errata and Security Advisory 2010:0978 respectively.
#

include("compat.inc");

if (description)
{
  script_id(51146);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/28 23:54:24 $");

  script_cve_id("CVE-2008-7270", "CVE-2010-4180");
  script_bugtraq_id(45164, 45254);
  script_osvdb_id(69565, 69655);
  script_xref(name:"RHSA", value:"2010:0978");

  script_name(english:"CentOS 5 : openssl (CESA-2010:0978)");
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

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A ciphersuite downgrade flaw was found in the OpenSSL SSL/TLS server
code. A remote attacker could possibly use this flaw to change the
ciphersuite associated with a cached session stored on the server, if
the server enabled the SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG option,
possibly forcing the client to use a weaker ciphersuite after resuming
the session. (CVE-2010-4180, CVE-2008-7270)

Note: With this update, setting the
SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG option has no effect and this
bug workaround can no longer be enabled.

All OpenSSL users should upgrade to these updated packages, which
contain a backported patch to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-December/017211.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04f6565d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-December/017212.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3401605"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-12.el5_5.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-12.el5_5.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-12.el5_5.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
