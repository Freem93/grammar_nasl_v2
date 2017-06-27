#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2779 and 
# CentOS Errata and Security Advisory 2016:2779 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94981);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2016-2834", "CVE-2016-5285", "CVE-2016-8635");
  script_osvdb_id(147521, 147522);
  script_xref(name:"RHSA", value:"2016:2779");

  script_name(english:"CentOS 5 / 6 / 7 : nss / nss-util (CESA-2016:2779)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nss and nss-util is now available for Red Hat Enterprise
Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version:
nss (3.12.3), nss-util (3.12.3).

Security Fix(es) :

* Multiple buffer handling flaws were found in the way NSS handled
cryptographic data from the network. A remote attacker could use these
flaws to crash an application using NSS or, possibly, execute
arbitrary code with the permission of the user running the
application. (CVE-2016-2834)

* A NULL pointer dereference flaw was found in the way NSS handled
invalid Diffie-Hellman keys. A remote client could use this flaw to
crash a TLS/SSL server using NSS. (CVE-2016-5285)

* It was found that Diffie Hellman Client key exchange handling in NSS
was vulnerable to small subgroup confinement attack. An attacker could
use this flaw to recover private keys by confining the client DH key
to small subgroup of the desired group. (CVE-2016-8635)

Red Hat would like to thank the Mozilla project for reporting
CVE-2016-2834. The CVE-2016-8635 issue was discovered by Hubert Kario
(Red Hat). Upstream acknowledges Tyson Smith and Jed Davis as the
original reporter of CVE-2016-2834."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-November/022151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eecc99fd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-November/022152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4730c5c1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-November/022159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61e0bd45"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003683.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afbd2b5e"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?643b1981"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"nss-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.21.3-2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.21.3-2.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"nss-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.21.3-2.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.21.3-1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.21.3-1.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-devel-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-sysinit-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-tools-3.21.3-2.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-3.21.3-1.1.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-util-devel-3.21.3-1.1.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
