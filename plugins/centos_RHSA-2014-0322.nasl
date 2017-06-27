#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0322 and 
# CentOS Errata and Security Advisory 2014:0322 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73163);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2012-6151", "CVE-2014-2285");
  script_bugtraq_id(64048, 65968);
  script_osvdb_id(101547, 104045);
  script_xref(name:"RHSA", value:"2014:0322");

  script_name(english:"CentOS 5 : net-snmp (CESA-2014:0322)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

A denial of service flaw was found in the way snmpd, the Net-SNMP
daemon, handled subagent timeouts. A remote attacker able to trigger a
subagent timeout could use this flaw to cause snmpd to loop infinitely
or crash. (CVE-2012-6151)

A denial of service flaw was found in the way the snmptrapd service,
which receives and logs SNMP trap messages, handled SNMP trap requests
with an empty community string when the Perl handler (provided by the
net-snmp-perl package) was enabled. A remote attacker could use this
flaw to crash snmptrapd by sending a trap request with an empty
community string. (CVE-2014-2285)

All net-snmp users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the snmpd and snmptrapd services will be
restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88bee755"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"net-snmp-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-devel-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-libs-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-perl-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-utils-5.3.2.2-22.el5_10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");