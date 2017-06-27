#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0684 and 
# CentOS Errata and Security Advisory 2016:0684 respectively.
#

include("compat.inc");

if (description)
{
  script_id(90721);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-1978", "CVE-2016-1979");
  script_osvdb_id(135604, 135718);
  script_xref(name:"RHSA", value:"2016:0684");

  script_name(english:"CentOS 5 : nspr / nss (CESA-2016:0684)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nss and nspr is now available for Red Hat Enterprise
Linux 5.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

The following packages have been upgraded to a newer upstream version:
nss 3.21.0, nspr 4.11.0. (BZ#1297944, BZ#1297943)

Security Fix(es) :

* A use-after-free flaw was found in the way NSS handled DHE
(Diffie-Hellman key exchange) and ECDHE (Elliptic Curve Diffie-Hellman
key exchange) handshake messages. A remote attacker could send a
specially crafted handshake message that, when parsed by an
application linked against NSS, would cause that application to crash
or, under certain special conditions, execute arbitrary code using the
permissions of the user running the application. (CVE-2016-1978)

* A use-after-free flaw was found in the way NSS processed certain DER
(Distinguished Encoding Rules) encoded cryptographic keys. An attacker
could use this flaw to create a specially crafted DER encoded
certificate which, when parsed by an application compiled against the
NSS library, could cause that application to crash, or execute
arbitrary code using the permissions of the user running the
application. (CVE-2016-1979)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Eric Rescorla as the original reporter
of CVE-2016-1978; and Tim Taubert as the original reporter of
CVE-2016-1979."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-April/021846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?519c5457"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-April/021847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44fcad9c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
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
if (rpm_check(release:"CentOS-5", reference:"nspr-4.11.0-1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.11.0-1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.21.0-6.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.21.0-6.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.21.0-6.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.21.0-6.el5_11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
