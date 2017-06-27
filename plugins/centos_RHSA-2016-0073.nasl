#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0073 and 
# CentOS Errata and Security Advisory 2016:0073 respectively.
#

include("compat.inc");

if (description)
{
  script_id(88420);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2015-8704");
  script_osvdb_id(133380);
  script_xref(name:"RHSA", value:"2016:0073");

  script_name(english:"CentOS 5 / 6 / 7 : bind (CESA-2016:0073)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix one security issue are now available
for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A denial of service flaw was found in the way BIND processed certain
malformed Address Prefix List (APL) records. A remote, authenticated
attacker could use this flaw to cause named to crash. (CVE-2015-8704)

Red Hat would like to thank ISC for reporting this issue.

All bind users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, the BIND daemon (named) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021630.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efceaa58"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5103fc01"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65d4b9ef"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/28");
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
if (rpm_check(release:"CentOS-5", reference:"bind-9.3.6-25.P1.el5_11.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.6-25.P1.el5_11.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.6-25.P1.el5_11.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.6-25.P1.el5_11.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.6-25.P1.el5_11.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.6-25.P1.el5_11.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.6-25.P1.el5_11.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.6-25.P1.el5_11.6")) flag++;

if (rpm_check(release:"CentOS-6", reference:"bind-9.8.2-0.37.rc1.el6_7.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-chroot-9.8.2-0.37.rc1.el6_7.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-devel-9.8.2-0.37.rc1.el6_7.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-libs-9.8.2-0.37.rc1.el6_7.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-sdb-9.8.2-0.37.rc1.el6_7.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-utils-9.8.2-0.37.rc1.el6_7.6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-chroot-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-devel-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-libs-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-libs-lite-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-license-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-lite-devel-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-devel-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-libs-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-pkcs11-utils-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-sdb-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-sdb-chroot-9.9.4-29.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bind-utils-9.9.4-29.el7_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
