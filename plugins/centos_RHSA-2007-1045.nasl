#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1045 and 
# CentOS Errata and Security Advisory 2007:1045 respectively.
#

include("compat.inc");

if (description)
{
  script_id(36614);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-5846");
  script_bugtraq_id(26378);
  script_osvdb_id(38904);
  script_xref(name:"RHSA", value:"2007:1045");

  script_name(english:"CentOS 3 / 4 : net-snmp (CESA-2007:1045)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

Simple Network Management Protocol (SNMP) is a protocol used for
network management.

A flaw was discovered in the way net-snmp handled certain requests. A
remote attacker who can connect to the snmpd UDP port (161 by default)
could send a malicious packet causing snmpd to crash, resulting in a
denial of service. (CVE-2007-5846)

All users of net-snmp are advised to upgrade to these updated
packages, which contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014433.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1dad24a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15531f0a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014440.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc7e36c2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d6f25bb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"net-snmp-5.0.9-2.30E.23")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-devel-5.0.9-2.30E.23")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-libs-5.0.9-2.30E.23")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-perl-5.0.9-2.30E.23")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-utils-5.0.9-2.30E.23")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-devel-5.1.2-11.c4.11.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-libs-5.1.2-11.c4.11.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-perl-5.1.2-11.c4.11.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-utils-5.1.2-11.c4.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
