#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1829 and 
# CentOS Errata and Security Advisory 2013:1829 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71380);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-1739", "CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607");
  script_bugtraq_id(62966, 63736, 63737, 63738, 63802);
  script_osvdb_id(89848, 98402, 99746, 99747, 99748);
  script_xref(name:"RHSA", value:"2013:1829");

  script_name(english:"CentOS 6 : nspr / nss / nss-util (CESA-2013:1829)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nspr, and nss-util packages that fix multiple security
issues are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way NSS handled invalid handshake packets. A
remote attacker could use this flaw to cause a TLS/SSL client using
NSS to crash or, possibly, execute arbitrary code with the privileges
of the user running the application. (CVE-2013-5605)

It was found that the fix for CVE-2013-1620 released via
RHSA-2013:1135 introduced a regression causing NSS to read
uninitialized data when a decryption failure occurred. A remote
attacker could use this flaw to cause a TLS/SSL server using NSS to
crash. (CVE-2013-1739)

An integer overflow flaw was discovered in both NSS and NSPR's
implementation of certification parsing on 64-bit systems. A remote
attacker could use these flaws to cause an application using NSS or
NSPR to crash. (CVE-2013-1741, CVE-2013-5607)

It was discovered that NSS did not reject certificates with
incompatible key usage constraints when validating them while the
verifyLog feature was enabled. An application using the NSS
certificate validation API could accept an invalid certificate.
(CVE-2013-5606)

Red Hat would like to thank the Mozilla project for reporting
CVE-2013-1741, CVE-2013-5606, and CVE-2013-5607. Upstream acknowledges
Tavis Ormandy as the original reporter of CVE-2013-1741, Camilo Viecco
as the original reporter of CVE-2013-5606, and Pascal Cuoq, Kamil
Dudka, and Wan-Teh Chang as the original reporters of CVE-2013-5607.

All NSS, NSPR, and nss-util users are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues. After installing this update, applications using NSS, NSPR, or
nss-util must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020069.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3579522"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020070.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18f588c3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020071.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32d4bf8f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr, nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"nspr-4.10.2-1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nspr-devel-4.10.2-1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.15.3-2.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.15.3-1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.15.3-1.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
