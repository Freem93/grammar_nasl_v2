#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1246 and 
# CentOS Errata and Security Advisory 2014:1246 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77993);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1545");
  script_bugtraq_id(64944, 65332, 65335, 66356, 67975);
  script_osvdb_id(102170, 102876, 102877, 104708, 107912);
  script_xref(name:"RHSA", value:"2014:1246");

  script_name(english:"CentOS 5 : nss (CESA-2014:1246)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nspr packages that fix multiple security issues,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

A flaw was found in the way TLS False Start was implemented in NSS. An
attacker could use this flaw to potentially return unencrypted
information from the server. (CVE-2013-1740)

A race condition was found in the way NSS implemented session ticket
handling as specified by RFC 5077. An attacker could use this flaw to
crash an application using NSS or, in rare cases, execute arbitrary
code with the privileges of the user running that application.
(CVE-2014-1490)

It was found that NSS accepted weak Diffie-Hellman Key exchange (DHKE)
parameters. This could possibly lead to weak encryption being used in
communication between the client and the server. (CVE-2014-1491)

An out-of-bounds write flaw was found in NSPR. A remote attacker could
potentially use this flaw to crash an application using NSPR or,
possibly, execute arbitrary code with the privileges of the user
running that application. This NSPR flaw was not exposed to web
content in any shipped version of Firefox. (CVE-2014-1545)

It was found that the implementation of Internationalizing Domain
Names in Applications (IDNA) hostname matching in NSS did not follow
the RFC 6125 recommendations. This could lead to certain invalid
certificates with international characters to be accepted as valid.
(CVE-2014-1492)

Red Hat would like to thank the Mozilla project for reporting the
CVE-2014-1490, CVE-2014-1491, and CVE-2014-1545 issues. Upstream
acknowledges Brian Smith as the original reporter of CVE-2014-1490,
Antoine Delignat-Lavaud and Karthikeyan Bhargavan as the original
reporters of CVE-2014-1491, and Abhishek Arya as the original reporter
of CVE-2014-1545.

The nss and nspr packages have been upgraded to upstream version
3.16.1 and 4.10.6 respectively, which provide a number of bug fixes
and enhancements over the previous versions. (BZ#1110857, BZ#1110860)

This update also fixes the following bugs :

* Previously, when the output.log file was not present on the system,
the shell in the Network Security Services (NSS) specification handled
test failures incorrectly as false positive test results.
Consequently, certain utilities, such as 'grep', could not handle
failures properly. This update improves error detection in the
specification file, and 'grep' and other utilities now handle missing
files or crashes as intended. (BZ#1035281)

* Prior to this update, a subordinate Certificate Authority (CA) of
the ANSSI agency incorrectly issued an intermediate certificate
installed on a network monitoring device. As a consequence, the
monitoring device was enabled to act as an MITM (Man in the Middle)
proxy performing traffic management of domain names or IP addresses
that the certificate holder did not own or control. The trust in the
intermediate certificate to issue the certificate for an MITM device
has been revoked, and such a device can no longer be used for MITM
attacks. (BZ#1042684)

* Due to a regression, MD5 certificates were rejected by default
because Network Security Services (NSS) did not trust MD5
certificates. With this update, MD5 certificates are supported in Red
Hat Enterprise Linux 5. (BZ#11015864)

Users of nss and nspr are advised to upgrade to these updated
packages, which correct these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020634.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63d8e3ab"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/01");
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
if (rpm_check(release:"CentOS-5", reference:"nss-3.16.1-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.16.1-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.16.1-2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.16.1-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
