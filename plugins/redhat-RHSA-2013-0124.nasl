#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0124. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63407);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-2141");
  script_bugtraq_id(53255);
  script_osvdb_id(81636);
  script_xref(name:"RHSA", value:"2013:0124");

  script_name(english:"RHEL 5 : net-snmp (RHSA-2013:0124)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix one security issue and multiple
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

These packages provide various libraries and tools for the Simple
Network Management Protocol (SNMP).

An out-of-bounds buffer read flaw was found in the net-snmp agent. A
remote attacker with read privileges to a Management Information Base
(MIB) subtree handled by the 'extend' directive (in
'/etc/snmp/snmpd.conf') could use this flaw to crash snmpd via a
crafted SNMP GET request. (CVE-2012-2141)

Bug fixes :

* Devices that used certain file systems were not reported in the
'HOST-RESOURCES-MIB::hrStorageTable' table. As a result, the snmpd
daemon did not recognize devices using tmpfs, ReiserFS, and Oracle
Cluster File System (OCFS2) file systems. This update recognizes these
devices and reports them in the 'HOST-RESOURCES-MIB::hrStorageTable'
table. (BZ#754652, BZ#755958, BZ#822061)

* The snmptrapd (8) man page did not correctly describe how to load
multiple configuration files using the '-c' option. This update
describes correctly that multiple configuration files must be
separated by a comma. (BZ#760001)

* Integers truncated from 64 to 32-bit were not correctly evaluated.
As a consequence, the snmpd daemon could enter an endless loop when
encoding the truncated integers to network format. This update
modifies the underlying code so that snmpd correctly checks truncated
64-bit integers. Now, snmpd avoids an endless loop. (BZ#783892)

* snmpd did not correctly check for interrupted system calls when
enumerating existing IPv6 network prefixes during startup. As a
consequence, snmpd could prematurely exit when receiving a signal
during this enumeration. This update checks the network prefix
enumeration code for interrupted system calls. Now, snmpd no longer
terminates when a signal is received. (BZ#799699)

* snmpd used the wrong length of COUNTER64 values in the AgentX
protocol. As a consequence, snmpd could not decode two consecutive
COUNTER64 values in one AgentX packet. This update uses the correct
COUNTER64 size and can process two or mode COUNTER64 values in AgentX
communication. (BZ#803585)

* snmpd ignored the '-e' parameter of the 'trapsess' option in the
snmpd configuration file. As a result, outgoing traps were incorrectly
sent with the default EngineID of snmpd when configuring 'trapsess'
with an explicit EngineID. This update modifies the underlying code to
send outgoing traps using the EngineID as specified in the 'trapsess
-e' parameter in the configuration file. (BZ#805689)

* snmpd did not correctly encode negative Request-IDs in outgoing
requests, for example during trap operations. As a consequence, a
32-bit value could be encoded in 5 bytes instead of 4, and the
outgoing requests were refused by certain implementations of the SNMP
protocol as invalid. With this update, a Request-ID can no longer
become negative and is always encoded in 4 bytes. (BZ#818259)

* snmpd ignored the port number of the 'clientaddr' option when
specifying the source address of outgoing SNMP requests. As a
consequence, the system assigned a random address. This update allows
to specify both the port number and the source IP address in the
'clientaddr' option. Now, administrators can increase security with
firewall rules and Security-Enhanced Linux (SELinux) policies by
configuring a specific source port of outgoing traps and other
requests. (BZ#828691)

* snmpd did not correctly process responses to internal queries when
initializing monitoring enabled by the 'monitor' option in the
'/etc/snmp/snmpd.conf' configuration file. As a consequence, snmpd was
not fully initialized and the error message 'failed to run mteTrigger
query' appeared in the system log 30 seconds after the snmpd startup.
This update explicitly checks for responses to internal monitoring
queries. (BZ#830042)

Users of net-snmp should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the snmpd and snmptrapd daemons will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0124.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0124";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"net-snmp-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"net-snmp-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"net-snmp-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"net-snmp-debuginfo-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"net-snmp-devel-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"net-snmp-libs-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"net-snmp-perl-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"net-snmp-perl-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"net-snmp-perl-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"net-snmp-utils-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"net-snmp-utils-5.3.2.2-20.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"net-snmp-utils-5.3.2.2-20.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
