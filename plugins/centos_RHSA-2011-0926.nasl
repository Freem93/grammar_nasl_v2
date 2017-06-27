#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0926 and 
# CentOS Errata and Security Advisory 2011:0926 respectively.
#

include("compat.inc");

if (description)
{
  script_id(55536);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:31:31 $");

  script_cve_id("CVE-2011-2464");
  script_bugtraq_id(48566);
  script_osvdb_id(73605);
  script_xref(name:"RHSA", value:"2011:0926");

  script_name(english:"CentOS 5 : bind97 (CESA-2011:0926)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind and bind97 packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was discovered in the way BIND handled certain DNS requests. A
remote attacker could use this flaw to send a specially crafted DNS
request packet to BIND, causing it to exit unexpectedly due to a
failed assertion. (CVE-2011-2464)

Users of bind97 on Red Hat Enterprise Linux 5, and bind on Red Hat
Enterprise Linux 6, are advised to upgrade to these updated packages,
which resolve this issue. After installing the update, the BIND daemon
(named) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-July/017643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00abd7fb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-July/017644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51984ecb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind97 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"bind97-9.7.0-6.P2.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-chroot-9.7.0-6.P2.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-devel-9.7.0-6.P2.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-libs-9.7.0-6.P2.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-utils-9.7.0-6.P2.el5_6.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
