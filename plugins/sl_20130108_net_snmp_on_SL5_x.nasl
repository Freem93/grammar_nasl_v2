#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63600);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 14:07:22 $");

  script_cve_id("CVE-2012-2141");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds buffer read flaw was found in the net-snmp agent. A
remote attacker with read privileges to a Management Information Base
(MIB) subtree handled by the 'extend' directive (in
'/etc/snmp/snmpd.conf') could use this flaw to crash snmpd via a
crafted SNMP GET request. (CVE-2012-2141)

Bug fixes :

  - Devices that used certain file systems were not reported
    in the 'HOST- RESOURCES-MIB::hrStorageTable' table. As a
    result, the snmpd daemon did not recognize devices using
    tmpfs, ReiserFS, and Oracle Cluster File System (OCFS2)
    file systems. This update recognizes these devices and
    reports them in the 'HOST-RESOURCES-MIB::hrStorageTable'
    table.

  - The snmptrapd (8) man page did not correctly describe
    how to load multiple configuration files using the '-c'
    option. This update describes correctly that multiple
    configuration files must be separated by a comma.

  - Integers truncated from 64 to 32-bit were not correctly
    evaluated. As a consequence, the snmpd daemon could
    enter an endless loop when encoding the truncated
    integers to network format. This update modifies the
    underlying code so that snmpd correctly checks truncated
    64-bit integers. Now, snmpd avoids an endless loop.

  - snmpd did not correctly check for interrupted system
    calls when enumerating existing IPv6 network prefixes
    during startup. As a consequence, snmpd could
    prematurely exit when receiving a signal during this
    enumeration. This update checks the network prefix
    enumeration code for interrupted system calls. Now,
    snmpd no longer terminates when a signal is received.

  - snmpd used the wrong length of COUNTER64 values in the
    AgentX protocol. As a consequence, snmpd could not
    decode two consecutive COUNTER64 values in one AgentX
    packet. This update uses the correct COUNTER64 size and
    can process two or mode COUNTER64 values in AgentX
    communication.

  - snmpd ignored the '-e' parameter of the 'trapsess'
    option in the snmpd configuration file. As a result,
    outgoing traps were incorrectly sent with the default
    EngineID of snmpd when configuring 'trapsess' with an
    explicit EngineID. This update modifies the underlying
    code to send outgoing traps using the EngineID as
    specified in the 'trapsess -e' parameter in the
    configuration file.

  - snmpd did not correctly encode negative Request-IDs in
    outgoing requests, for example during trap operations.
    As a consequence, a 32-bit value could be encoded in 5
    bytes instead of 4, and the outgoing requests were
    refused by certain implementations of the SNMP protocol
    as invalid. With this update, a Request-ID can no longer
    become negative and is always encoded in 4 bytes.

  - snmpd ignored the port number of the 'clientaddr' option
    when specifying the source address of outgoing SNMP
    requests. As a consequence, the system assigned a random
    address. This update allows to specify both the port
    number and the source IP address in the 'clientaddr'
    option. Now, administrators can increase security with
    firewall rules and Security-Enhanced Linux (SELinux)
    policies by configuring a specific source port of
    outgoing traps and other requests.

  - snmpd did not correctly process responses to internal
    queries when initializing monitoring enabled by the
    'monitor' option in the '/etc/snmp/snmpd.conf'
    configuration file. As a consequence, snmpd was not
    fully initialized and the error message 'failed to run
    mteTrigger query' appeared in the system log 30 seconds
    after the snmpd startup. This update explicitly checks
    for responses to internal monitoring queries.

After installing the update, the snmpd and snmptrapd daemons will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=1209
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1188b02b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"net-snmp-5.3.2.2-20.el5")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-debuginfo-5.3.2.2-20.el5")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-devel-5.3.2.2-20.el5")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-libs-5.3.2.2-20.el5")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-perl-5.3.2.2-20.el5")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-utils-5.3.2.2-20.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
