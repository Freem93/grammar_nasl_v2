#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:373 and 
# CentOS Errata and Security Advisory 2005:373 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21812);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2005-1740", "CVE-2005-2177", "CVE-2005-4837");
  script_osvdb_id(16778, 17754);
  script_xref(name:"RHSA", value:"2005:373");

  script_name(english:"CentOS 3 : net-snmp (CESA-2005:373)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix two security issues and various
bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

SNMP (Simple Network Management Protocol) is a protocol used for
network management.

A denial of service bug was found in the way net-snmp uses network
stream protocols. It is possible for a remote attacker to send a
net-snmp agent a specially crafted packet which will crash the agent.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-2177 to this issue.

An insecure temporary file usage bug was found in net-snmp's fixproc
command. It is possible for a local user to modify the content of
temporary files used by fixproc which can lead to arbitrary command
execution. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1740 to this issue.

Additionally the following bugs have been fixed: - snmpwalk no longer
hangs when a non-existent pid is listed. - snmpd no longer segfaults
due to incorrect handling of lmSensors. - an incorrect assignment
leading to invalid values in ASN mibs has been fixed. - on systems
running a 64-bit kernel, the values in /proc/net/dev no longer become
too large to fit in a 32-bit object. - the net-snmp-devel packages
correctly depend on elfutils-libelf-devel. - large file systems are
correctly handled - snmp daemon now reports gigabit Ethernet speeds
correctly - fixed consistency between IP adresses and hostnames in
configuration file

All users of net-snmp should upgrade to these updated packages, which
resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4bccdfb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012227.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e286d0d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c38d3b08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"net-snmp-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-devel-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-libs-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-perl-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-utils-5.0.9-2.30E.19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
