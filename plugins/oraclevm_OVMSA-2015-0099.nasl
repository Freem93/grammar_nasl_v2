#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0099.
#

include("compat.inc");

if (description)
{
  script_id(85140);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2014-2284", "CVE-2014-3565");
  script_bugtraq_id(65867, 69477);
  script_osvdb_id(110884, 130393);

  script_name(english:"OracleVM 3.3 : net-snmp (OVMSA-2015-0099)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Add Oracle ACFS to hrStorage (John Haxby) [orabug
    18510373]

  - Quicker loading of IP-MIB::ipAddrTable (#1191393)

  - Quicker loading of IP-MIB::ipAddressTable (#1191393)

  - Fixed snmptrapd crash when '-OQ' parameter is used and
    invalid trap is received (#CVE-2014-3565)

  - added faster caching into IP-MIB::ipNetToMediaTable
    (#789500)

  - fixed compilation with '-Werror=format-security'
    (#1181994)

  - added clear error message when port specified in
    'clientaddrr' config option cannot be bound (#886468)

  - fixed error check in IP-MIB::ipAddressTable (#1012430)

  - fixed agentx client crash on failed response (#1023570)

  - fixed dashes in net-snmp-config.h (#1034441)

  - fixed crash on monitor trigger (#1050970)

  - fixed 'netsnmp_assert 1 == new_val->high failed' message
    in system log (#1065210)

  - fixed parsing of 64bit counters from SMUX subagents
    (#1069046)

  - Fixed HOST-RESOURCES-MIB::hrProcessorTable on machines
    with >100 CPUs (#1070075)

  - fixed net-snmp-create-v3-user to have the same content
    on 32 and 64bit installations (#1073544)

  - fixed IPADDRESS value length in Python bindings
    (#1100099)

  - fixed hrStorageTable to contain 31 bits integers
    (#1104293)

  - fixed links to developer man pages (#1119567)

  - fixed storageUseNFS functionality in hrStorageTable
    (#1125793)

  - fixed netsnmp_set Python bindings call truncating at the
    first '\000' character (#1126914)

  - fixed log level of SMUX messages (#1140234)

  - use python/README to net-snmp-python subpackage
    (#1157373)

  - fixed forwarding of traps with RequestID=0 in snmptrapd
    (#1146948)

  - fixed typos in NET-SNMP-PASS-MIB and SMUX-MIB (#1162040)

  - fixed close overhead of extend commands (#1188295)

  - fixed lmSensorsTable not reporting sensors with
    duplicate names (#967871)

  - fixed hrDeviceTable with interfaces with large ifIndex
    (#1195547)

  - added 'diskio' option to snmpd.conf, it's possible to
    monitor only selected devices in diskIOTable (#990674)

  - fixed CVE-2014-2284: denial of service flaw in Linux
    implementation of ICMP-MIB (#1073223)

  - added cache to hrSWRunTable to provide consistent
    results (#1007634)

  - skip 'mvfs' (ClearCase) when skipNFSInHostResources is
    enabled (#1073237)

  - fixed snmptrapd crashing on forwarding SNMPv3 traps
    (#1131844)

  - fixed HOST-RESOURCES-MIB::hrSystemProcesses (#1134335)

  - fixed snmp daemons and utilities crashing in FIPS mode
    (#1001830)

  - added support of btrfs filesystem in hrStorageTable
    (#1006706)

  - fixed issues found by static analysis tools

  - restored ABI of read_configs_* functions

  - fixed parsing of bulk responses (#983116)

  - added support of vzfs filesystem in hrStorageTable
    (#989498)

  - fixed endless loop when parsing sendmail configuration
    file with queue groups (#991213)

  - fixed potential memory leak on realloc failure when
    processing 'extend' option (#893119)

  - added precise enumeration of configuration files
    searched to snmp_config(5) man page (#907571)

  - set permissions of snmpd.conf and snmptrapd conf to 0600
    (#919239)

  - fixed kernel threads in hrSWRunTable (#919952)

  - fixed various error codes in Python module (#955771)

  - fixed snmpd crashing in the middle of agentx request
    processing when a subagent disconnects (#955511)

  - allow 'includeFile' and 'includeDir' options in
    configuration files (#917816)

  - fixed netlink message size (#927474)

  - fixed IF-MIB::ifSpeedHi on systems with non-standard
    interface speeds (#947973)

  - fixed BRIDGE-MIB::dot1dBasePortTable not to include the
    bridge itself as a port (#960568)

  - fixed snmpd segfault when 'agentaddress' configuration
    options is used and too many SIGHUP signals are received
    (#968898)

  - updated UCD-SNMP-MIB::dskTable to dynamically add/remove
    disks if 'includeAllDisks' is specified in snmpd.conf
    (#922691)

  - fixed crash when parsing invalid SNMP packets (#953926)

  - fixed snmpd crashing with 'exec' command with no
    arguments in snmpd.conf (#919259)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-July/000349.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected net-snmp / net-snmp-libs / net-snmp-utils
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"net-snmp-5.5-54.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"net-snmp-libs-5.5-54.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"net-snmp-utils-5.5-54.0.1.el6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-libs / net-snmp-utils");
}
