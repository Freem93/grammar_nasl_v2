#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1556-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85942);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/05 21:24:25 $");

  script_cve_id("CVE-2015-5621");
  script_osvdb_id(121026);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : net-snmp (SUSE-SU-2015:1556-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following issues have been fixed within this update :

  - fix btrfs output inside
    HOST-RESOURCES-MIB::hrStorageDescr. (bsc#909479)

  - fix an incompletely initialized vulnerability within the
    snmp_pdu_parse() function of snmp_api.c. (bsc#940188,
    CVE-2015-5621)

  - add build requirement 'procps' to fix a net-snmp-config
    error (bsc#935863)

  - --disable-md5 to allow operation in FIPS mode and not
    use the old algorithm (bsc#935876 bsc#940084)

  - also stop snmptrapd on removal

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5621.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151556-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec403c73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-537=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-537=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-537=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsnmp30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:net-snmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-SNMP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsnmp30-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsnmp30-debuginfo-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"net-snmp-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"net-snmp-debuginfo-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"net-snmp-debugsource-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-SNMP-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-SNMP-debuginfo-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"snmp-mibs-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsnmp30-32bit-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsnmp30-debuginfo-32bit-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsnmp30-32bit-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsnmp30-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsnmp30-debuginfo-32bit-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsnmp30-debuginfo-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"net-snmp-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"net-snmp-debuginfo-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"net-snmp-debugsource-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"perl-SNMP-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"perl-SNMP-debuginfo-5.7.2.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"snmp-mibs-5.7.2.1-4.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp");
}
