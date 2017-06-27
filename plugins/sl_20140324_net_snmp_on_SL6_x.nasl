#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(73177);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/26 10:46:23 $");

  script_cve_id("CVE-2014-2284");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL6.x i386/x86_64");
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
"A buffer overflow flaw was found in the way the decode_icmp_msg()
function in the ICMP-MIB implementation processed Internet Control
Message Protocol (ICMP) message statistics reported in the
/proc/net/snmp file. A remote attacker could send a message for each
ICMP message type, which could potentially cause the snmpd service to
crash when processing the /proc/net/snmp file. (CVE-2014-2284)

This update also fixes the following bug :

  - The snmpd service parses the /proc/diskstats file to
    track disk usage statistics for
    UCD-DISKIO-MIB::diskIOTable. On systems with a large
    number of block devices, /proc/diskstats may be large in
    size and parsing it can take a non-trivial amount of CPU
    time. With this update, Net-SNMP introduces a new
    option, 'diskio', in the /etc/snmp/snmpd.conf file,
    which can be used to explicitly specify devices that
    should be monitored. Only these whitelisted devices are
    then reported in UCD-DISKIO- MIB::diskIOTable, thus
    speeding up snmpd on systems with numerous block
    devices.

After installing this update, the snmpd service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=2089
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e97f4f21"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"net-snmp-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-debuginfo-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-devel-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-libs-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-perl-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-python-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-utils-5.5-49.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
