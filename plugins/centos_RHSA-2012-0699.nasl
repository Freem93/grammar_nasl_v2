#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0699 and 
# CentOS Errata and Security Advisory 2012:0699 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59294);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2012-2333");
  script_bugtraq_id(53476);
  script_osvdb_id(81810);
  script_xref(name:"RHSA", value:"2012:0699");

  script_name(english:"CentOS 5 / 6 : openssl (CESA-2012:0699)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An integer underflow flaw, leading to a buffer over-read, was found in
the way OpenSSL handled DTLS (Datagram Transport Layer Security)
application data record lengths when using a block cipher in CBC
(cipher-block chaining) mode. A malicious DTLS client or server could
use this flaw to crash its DTLS connection peer. (CVE-2012-2333)

Red Hat would like to thank the OpenSSL project for reporting this
issue. Upstream acknowledges Codenomicon as the original reporter.

On Red Hat Enterprise Linux 6, this update also fixes an uninitialized
variable use bug, introduced by the fix for CVE-2012-0884 (released
via RHSA-2012:0426). This bug could possibly cause an attempt to
create an encrypted message in the CMS (Cryptographic Message Syntax)
format to fail.

All OpenSSL users should upgrade to these updated packages, which
contain a backported patch to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2012-May/018659.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2012-May/018660.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-22.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-22.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-22.el5_8.4")) flag++;

if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.0-20.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.0-20.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.0-20.el6_2.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.0-20.el6_2.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
