#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61342);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/16 11:07:46 $");

  script_cve_id("CVE-2012-2141");

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
"The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

An array index error, leading to an out-of-bounds buffer read flaw,
was found in the way the net-snmp agent looked up entries in the
extension table. A remote attacker with read privileges to a
Management Information Base (MIB) subtree handled by the 'extend'
directive (in '/etc/snmp/snmpd.conf') could use this flaw to crash
snmpd via a crafted SNMP GET request. (CVE-2012-2141)

These updated net-snmp packages also include numerous bug fixes.

All users of net-snmp are advised to upgrade to these updated
packages, which contain backported patches to resolve these issues.
After installing the update, the snmpd and snmptrapd daemons will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=2679
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8aa2ac0a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"net-snmp-5.5-41.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-debuginfo-5.5-41.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-devel-5.5-41.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-libs-5.5-41.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-perl-5.5-41.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-python-5.5-41.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-utils-5.5-41.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
