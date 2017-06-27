#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1115 and 
# CentOS Errata and Security Advisory 2015:1115 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84199);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2014-8176", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-3216");
  script_bugtraq_id(75154, 75156, 75157, 75159, 75161);
  script_osvdb_id(122875, 123006, 123173, 123174, 123175, 123176);
  script_xref(name:"RHSA", value:"2015:1115");

  script_name(english:"CentOS 6 / 7 : openssl (CESA-2015:1115)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An invalid free flaw was found in the way OpenSSL handled certain DTLS
handshake messages. A malicious DTLS client or server could cause a
DTLS server or client using OpenSSL to crash or, potentially, execute
arbitrary code. (CVE-2014-8176)

A flaw was found in the way the OpenSSL packages shipped with Red Hat
Enterprise Linux 6 and 7 performed locking in the ssleay_rand_bytes()
function. This issue could possibly cause a multi-threaded application
using OpenSSL to perform an out-of-bounds read and crash.
(CVE-2015-3216)

An out-of-bounds read flaw was found in the X509_cmp_time() function
of OpenSSL. A specially crafted X.509 certificate or a Certificate
Revocation List (CRL) could possibly cause a TLS/SSL server or client
using OpenSSL to crash. (CVE-2015-1789)

A race condition was found in the session handling code of OpenSSL.
This issue could possibly cause a multi-threaded TLS/SSL client using
OpenSSL to double free session ticket data and crash. (CVE-2015-1791)

A flaw was found in the way OpenSSL handled Cryptographic Message
Syntax (CMS) messages. A CMS message with an unknown hash function
identifier could cause an application using OpenSSL to enter an
infinite loop. (CVE-2015-1792)

A NULL pointer dereference was found in the way OpenSSL handled
certain PKCS#7 inputs. A specially crafted PKCS#7 input with missing
EncryptedContent data could cause an application using OpenSSL to
crash. (CVE-2015-1790)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2014-8176, CVE-2015-1789, CVE-2015-1790, CVE-2015-1791 and
CVE-2015-1792 flaws. Upstream acknowledges Praveen Kariyanahalli and
Ivan Fratric as the original reporters of CVE-2014-8176, Robert
Swiecki and Hanno Bock as the original reporters of CVE-2015-1789,
Michal Zalewski as the original reporter of CVE-2015-1790, Emilia
Kasper as the original report of CVE-2015-1791 and Johannes Bauer as
the original reporter of CVE-2015-1792.

All openssl users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?105b72c1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1550045c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");
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
if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.1e-30.el6.11")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.1e-30.el6.11")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.1e-30.el6.11")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.1e-30.el6.11")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-1.0.1e-42.el7.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-42.el7.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-42.el7.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-42.el7.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-static-1.0.1e-42.el7.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
