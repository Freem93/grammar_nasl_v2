#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0257-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88454);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id("CVE-2009-0689", "CVE-2012-3543");
  script_bugtraq_id(35510, 36565, 36851, 37078, 37080, 37687, 37688, 55251);
  script_osvdb_id(55603, 61091, 61186, 61187, 61188, 61189, 62402, 63639, 63641, 63646, 85008, 132144);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : mono-core (SUSE-SU-2016:0257-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mono-core was updated to fix the following vulnerabilities :

  - CVE-2009-0689: Remote attackers could cause a denial of
    service and possibly arbitrary code execution through
    the string-to-double parser implementation (bsc#958097)

  - CVE-2012-3543: Remote attackers could cause a denial of
    service through increased CPU consumption due to lack of
    protection against predictable hash collisions when
    processing form parameters (bsc#739119)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/739119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2009-0689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-3543.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160257-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97605f9d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-mono-core-12369=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-mono-core-12369=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-mono-core-12369=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-mono-core-12369=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-mono-core-12369=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-mono-core-12369=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-wcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:monodoc-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-core-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-data-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-data-postgresql-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-data-sqlite-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-locale-extras-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-nunit-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-web-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mono-winforms-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-core-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-data-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-data-postgresql-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-data-sqlite-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-locale-extras-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-nunit-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-web-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mono-winforms-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"bytefx-data-mysql-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"ibm-data-db2-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-core-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-data-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-data-firebird-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-data-oracle-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-data-postgresql-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-data-sqlite-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-data-sybase-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-devel-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-extras-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-jscript-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-locale-extras-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-nunit-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-wcf-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-web-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mono-winforms-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"monodoc-core-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"bytefx-data-mysql-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"ibm-data-db2-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-core-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-data-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-data-firebird-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-data-oracle-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-data-postgresql-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-data-sqlite-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-data-sybase-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-devel-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-extras-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-jscript-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-locale-extras-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-nunit-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-wcf-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-web-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mono-winforms-2.6.7-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"monodoc-core-2.6.7-0.16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mono-core");
}
