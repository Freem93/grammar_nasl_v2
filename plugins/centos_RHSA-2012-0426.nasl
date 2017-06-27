#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0426 and 
# CentOS Errata and Security Advisory 2012:0426 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58502);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-0884", "CVE-2012-1165");
  script_bugtraq_id(52428);
  script_osvdb_id(80039, 80040);
  script_xref(name:"RHSA", value:"2012:0426");

  script_name(english:"CentOS 5 / 6 : openssl (CESA-2012:0426)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix two security issues and one bug are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A NULL pointer dereference flaw was found in the way OpenSSL parsed
Secure/Multipurpose Internet Mail Extensions (S/MIME) messages. An
attacker could use this flaw to crash an application that uses OpenSSL
to decrypt or verify S/MIME messages. (CVE-2012-1165)

A flaw was found in the PKCS#7 and Cryptographic Message Syntax (CMS)
implementations in OpenSSL. An attacker could possibly use this flaw
to perform a Bleichenbacher attack to decrypt an encrypted CMS,
PKCS#7, or S/MIME message by sending a large number of chosen
ciphertext messages to a service using OpenSSL and measuring error
response times. (CVE-2012-0884)

This update also fixes a regression caused by the fix for
CVE-2011-4619, released via RHSA-2012:0060 and RHSA-2012:0059, which
caused Server Gated Cryptography (SGC) handshakes to fail.

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-March/018528.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c10d5440"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-March/018530.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75861e49"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-22.el5_8.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-22.el5_8.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-22.el5_8.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.0-20.el6_2.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.0-20.el6_2.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.0-20.el6_2.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.0-20.el6_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
