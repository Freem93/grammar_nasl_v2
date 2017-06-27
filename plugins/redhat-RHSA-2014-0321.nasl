#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0321. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73174);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2014-2284");
  script_bugtraq_id(65867);
  script_xref(name:"RHSA", value:"2014:0321");

  script_name(english:"RHEL 6 : net-snmp (RHSA-2014:0321)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

A buffer overflow flaw was found in the way the decode_icmp_msg()
function in the ICMP-MIB implementation processed Internet Control
Message Protocol (ICMP) message statistics reported in the
/proc/net/snmp file. A remote attacker could send a message for each
ICMP message type, which could potentially cause the snmpd service to
crash when processing the /proc/net/snmp file. (CVE-2014-2284)

This update also fixes the following bug :

* The snmpd service parses the /proc/diskstats file to track disk
usage statistics for UCD-DISKIO-MIB::diskIOTable. On systems with a
large number of block devices, /proc/diskstats may be large in size
and parsing it can take a non-trivial amount of CPU time. With this
update, Net-SNMP introduces a new option, 'diskio', in the
/etc/snmp/snmpd.conf file, which can be used to explicitly specify
devices that should be monitored. Only these whitelisted devices are
then reported in UCD-DISKIO-MIB::diskIOTable, thus speeding up snmpd
on systems with numerous block devices. (BZ#990674)

All net-snmp users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the snmpd service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2284.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0321.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0321";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"net-snmp-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"net-snmp-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"net-snmp-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"net-snmp-debuginfo-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"net-snmp-devel-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"net-snmp-libs-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"net-snmp-perl-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"net-snmp-perl-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"net-snmp-perl-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"net-snmp-python-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"net-snmp-python-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"net-snmp-python-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"net-snmp-utils-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"net-snmp-utils-5.5-49.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"net-snmp-utils-5.5-49.el6_5.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-debuginfo / net-snmp-devel / net-snmp-libs / etc");
  }
}
