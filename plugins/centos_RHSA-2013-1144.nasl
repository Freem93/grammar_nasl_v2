#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1144 and 
# CentOS Errata and Security Advisory 2013:1144 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69247);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/06 23:41:35 $");

  script_cve_id("CVE-2013-0791", "CVE-2013-1620");
  script_bugtraq_id(57777, 58826);
  script_xref(name:"RHSA", value:"2013:1144");

  script_name(english:"CentOS 6 : nss / nss-util / nss-softokn / nspr (CESA-2013:1144)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nss-util, nss-softokn, and nspr packages that fix two
security issues, various bugs, and add enhancements are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.
nss-softokn provides an NSS softoken cryptographic module.

It was discovered that NSS leaked timing information when decrypting
TLS/SSL and DTLS protocol encrypted records when CBC-mode cipher
suites were used. A remote attacker could possibly use this flaw to
retrieve plain text from the encrypted packets by using a TLS/SSL or
DTLS server as a padding oracle. (CVE-2013-1620)

An out-of-bounds memory read flaw was found in the way NSS decoded
certain certificates. If an application using NSS decoded a malformed
certificate, it could cause the application to crash. (CVE-2013-0791)

Red Hat would like to thank the Mozilla project for reporting
CVE-2013-0791. Upstream acknowledges Ambroz Bizjak as the original
reporter of CVE-2013-0791.

This update also fixes the following bugs :

* The RHBA-2013:0445 update (which upgraded NSS to version 3.14)
prevented the use of certificates that have an MD5 signature. This
caused problems in certain environments. With this update,
certificates that have an MD5 signature are once again allowed. To
prevent the use of certificates that have an MD5 signature, set the
'NSS_HASH_ALG_SUPPORT' environment variable to '-MD5'. (BZ#957603)

* Previously, the sechash.h header file was missing, preventing
certain source RPMs (such as firefox and xulrunner) from building.
(BZ#948715)

* A memory leak in the nssutil_ReadSecmodDB() function has been fixed.
(BZ#984967)

In addition, the nss package has been upgraded to upstream version
3.14.3, the nss-util package has been upgraded to upstream version
3.14.3, the nss-softokn package has been upgraded to upstream version
3.14.3, and the nspr package has been upgraded to upstream version
4.9.5. These updates provide a number of bug fixes and enhancements
over the previous versions. (BZ#927157, BZ#927171, BZ#927158,
BZ#927186)

Users of NSS, NSPR, nss-util, and nss-softokn are advised to upgrade
to these updated packages, which fix these issues and add these
enhancements. After installing this update, applications using NSS,
NSPR, nss-util, or nss-softokn must be restarted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-August/019896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8632ed10"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"nspr-4.9.5-2.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nspr-devel-4.9.5-2.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-devel-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-freebl-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-freebl-devel-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.14.3-4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.14.3-3.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.14.3-3.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
