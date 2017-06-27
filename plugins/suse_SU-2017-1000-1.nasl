#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1000-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(99358);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/04/21 16:53:28 $");

  script_cve_id("CVE-2016-2775", "CVE-2016-6170", "CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138");
  script_osvdb_id(141063, 141681, 155529, 155530, 155531);
  script_xref(name:"IAVA", value:"2017-A-0004");
  script_xref(name:"IAVA", value:"2017-A-0120");

  script_name(english:"SUSE SLES11 Security Update : bind (SUSE-SU-2017:1000-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bind fixes the following security issues:
CVE-2017-3137 (bsc#1033467): Mistaken assumptions about the ordering
of records in the answer section of a response containing CNAME or
DNAME resource records could have been exploited to cause a denial of
service of a bind server performing recursion. CVE-2017-3136
(bsc#1033466): An attacker could have constructed a query that would
cause a denial of service of servers configured to use DNS64.
CVE-2017-3138 (bsc#1033468): An attacker with access to the BIND
control channel could have caused the server to stop by triggering an
assertion failure. CVE-2016-6170 (bsc#987866): Primary DNS servers
could have caused a denial of service of secondary DNS servers via a
large AXFR response. IXFR servers could have caused a denial of
service of IXFR clients via a large IXFR response. Remote
authenticated users could have caused a denial of service of primary
DNS servers via a large UPDATE message. CVE-2016-2775 (bsc#989528):
When lwresd or the named lwres option were enabled, bind allowed
remote attackers to cause a denial of service (daemon crash) via a
long request that uses the lightweight resolver protocol.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3138.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171000-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aeeee65f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-bind-13060=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-bind-13060=1

SUSE Manager 2.1:zypper in -t patch sleman21-bind-13060=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-bind-13060=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-bind-13060=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-bind-13060=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-bind-13060=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-bind-13060=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-bind-13060=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"bind-libs-32bit-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"bind-libs-32bit-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-chrootenv-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-doc-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-libs-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-utils-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"bind-libs-32bit-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"bind-libs-32bit-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-chrootenv-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-devel-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-doc-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-libs-9.9.6P1-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-utils-9.9.6P1-0.44.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
