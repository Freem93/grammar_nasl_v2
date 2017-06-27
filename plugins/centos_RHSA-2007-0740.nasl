#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0740 and 
# CentOS Errata and Security Advisory 2007:0740 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25778);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/08/31 14:21:47 $");

  script_cve_id("CVE-2007-2926");
  script_bugtraq_id(25037);
  script_osvdb_id(36235);
  script_xref(name:"RHSA", value:"2007:0740");

  script_name(english:"CentOS 3 / 4 / 5 : bind (CESA-2007:0740)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ISC BIND (Berkeley Internet Name Domain) is an implementation of the
DNS (Domain Name System) protocols.

A flaw was found in the way BIND generates outbound DNS query ids. If
an attacker is able to acquire a finite set of query IDs, it becomes
possible to accurately predict future query IDs. Future query ID
prediction may allow an attacker to conduct a DNS cache poisoning
attack, which can result in the DNS server returning incorrect client
query data. (CVE-2007-2926)

Users of BIND are advised to upgrade to these updated packages, which
contain backported patches to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014073.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32f5f1c3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014074.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f581bf6d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67267893"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f70358d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014078.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24589c65"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a97ebc3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014080.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98a2a6d7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014081.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a392de9d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"bind-9.2.4-21.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-chroot-9.2.4-21.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-devel-9.2.4-21.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-libs-9.2.4-21.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-utils-9.2.4-21.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"bind-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-chroot-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-devel-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-libs-9.2.4-27.0.1.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-utils-9.2.4-27.0.1.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"bind-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.3-9.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.3-9.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
