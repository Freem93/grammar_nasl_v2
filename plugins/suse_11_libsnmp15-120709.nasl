#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64194);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2012-2141");

  script_name(english:"SuSE 11.1 Security Update : net-snmp (SAT Patch Number 6517)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to net-snmp resolves the following issues :

  - Specially crafted SNMP GET requests could cause a denial
    of service (application crash) via a heap-based
    out-out-bounds read flaw which could be exploited
    remotely. (CVE-2012-2141)

  - The snmpd agent should read shared memory information
    from /proc/meminfo when running on Linux Kernel 2.6 or
    newer. (bnc#762887)

  - The snmpd agent could crash when an AgentX sub-agent
    disconnects in the middle of a request. (bnc#670789)

  - After rotating the net-snmp log file, use 'try-restart'
    to restart the daemon. Reloading with a SIGHUP signal
    may trigger crashes when dynamic modules (dlmod) are in
    use. (bnc#762433)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2141.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6517.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsnmp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsnmp15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libsnmp15-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"net-snmp-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"perl-SNMP-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"snmp-mibs-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libsnmp15-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libsnmp15-32bit-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"net-snmp-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"perl-SNMP-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"snmp-mibs-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libsnmp15-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"net-snmp-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"perl-SNMP-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"snmp-mibs-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libsnmp15-32bit-5.4.2.1-8.12.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libsnmp15-32bit-5.4.2.1-8.12.10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
