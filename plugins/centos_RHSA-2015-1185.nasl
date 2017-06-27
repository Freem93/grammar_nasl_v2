#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1185 and 
# CentOS Errata and Security Advisory 2015:1185 respectively.
#

include("compat.inc");

if (description)
{
  script_id(84405);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-4000");
  script_bugtraq_id(74733);
  script_osvdb_id(122331);
  script_xref(name:"RHSA", value:"2015:1185");

  script_name(english:"CentOS 6 / 7 : nss / nss-util (CESA-2015:1185) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nss-util packages that fix one security issue, several
bugs and add various enhancements are now available for Red Hat
Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications.

A flaw was found in the way the TLS protocol composes the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them do decrypt all traffic.
(CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in NSS to
reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Future updates may raise this limit
to 1024 bits.

The nss and nss-util packages have been upgraded to upstream versions
3.19.1. The upgraded versions provide a number of bug fixes and
enhancements over the previous versions.

Users of nss and nss-util are advised to upgrade to these updated
packages, which fix these security flaws, bugs, and add these
enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021219.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?882d54c4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021220.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b6bce4a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba1d573e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?253789ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:T/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/26");
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
if (rpm_check(release:"CentOS-6", reference:"nss-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.19.1-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.19.1-1.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.19.1-1.el6_6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-devel-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-sysinit-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-tools-3.19.1-3.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-3.19.1-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-devel-3.19.1-1.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
