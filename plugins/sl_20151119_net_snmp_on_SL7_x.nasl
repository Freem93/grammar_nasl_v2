#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87562);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2014-3565");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL7.x x86_64");
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
"A denial of service flaw was found in the way snmptrapd handled
certain SNMP traps when started with the '-OQ' option. If an attacker
sent an SNMP trap containing a variable with a NULL type where an
integer variable type was expected, it would cause snmptrapd to crash.
(CVE-2014-3565)

This update also fixes the following bugs :

  - Previously, the clientaddr option in the snmp.conf file
    affected outgoing messages sent only over IPv4. With
    this release, outgoing IPv6 messages are correctly sent
    from the interface specified by clientaddr.

  - The Net-SNMP daemon, snmpd, did not properly clean
    memory when reloading its configuration file with
    multiple 'exec' entries. Consequently, the daemon
    terminated unexpectedly. Now, the memory is properly
    cleaned, and snmpd no longer crashes on reload.

  - Prior to this update, snmpd did not parse complete IPv4
    traffic statistics, but reported the number of received
    or sent bytes in the IP- MIB::ipSystemStatsTable only
    for IPv6 packets and not for IPv4. This affected objects
    ipSystemStatsInOctets, ipSystemStatsOutOctets,
    ipSystemStatsInMcastOctets, and
    ipSystemStatsOutMcastOctets. Now, the statistics
    reported by snmpd are collected for IPv4 as well.

  - The Net-SNMP daemon, snmpd, did not correctly detect the
    file system change from read-only to read-write.
    Consequently, after remounting the file system into the
    read-write mode, the daemon reported it to be still in
    the read-only mode. A patch has been applied, and snmpd
    now detects the mode changes as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=6297
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a240b5b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-agent-libs-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-debuginfo-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-devel-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-gui-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-libs-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-perl-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-python-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-sysvinit-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-utils-5.7.2-24.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
