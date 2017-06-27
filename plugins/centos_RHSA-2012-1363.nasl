#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1363 and 
# CentOS Errata and Security Advisory 2012:1363 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62523);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2012-5166");
  script_osvdb_id(86118);
  script_xref(name:"RHSA", value:"2012:1363");

  script_name(english:"CentOS 5 / 6 : bind (CESA-2012:1363)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the way BIND handled certain combinations of
resource records. A remote attacker could use this flaw to cause a
recursive resolver, or an authoritative server in certain
configurations, to lockup. (CVE-2012-5166)

Users of bind are advised to upgrade to these updated packages, which
correct this issue. After installing the update, the BIND daemon
(named) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018934.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74ca0f31"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018938.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?121e9905"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/15");
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
if (rpm_check(release:"CentOS-5", reference:"bind-9.3.6-20.P1.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.6-20.P1.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.6-20.P1.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.6-20.P1.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.6-20.P1.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.6-20.P1.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.6-20.P1.el5_8.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.6-20.P1.el5_8.5")) flag++;

if (rpm_check(release:"CentOS-6", reference:"bind-9.8.2-0.10.rc1.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-chroot-9.8.2-0.10.rc1.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-devel-9.8.2-0.10.rc1.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-libs-9.8.2-0.10.rc1.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-sdb-9.8.2-0.10.rc1.el6_3.5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bind-utils-9.8.2-0.10.rc1.el6_3.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
