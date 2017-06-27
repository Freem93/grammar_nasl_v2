#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0112-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96434);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2016-9131", "CVE-2016-9147", "CVE-2016-9444");
  script_osvdb_id(149959, 149960, 149961);

  script_name(english:"SUSE SLES11 Security Update : bind (SUSE-SU-2017:0112-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bind fixes the following issues :

  - Fix a potential assertion failure that could have been
    triggered by a malformed response to an ANY query,
    thereby facilitating a denial-of-service attack.
    [CVE-2016-9131, bsc#1018700, bsc#1018699]

  - Fix a potential assertion failure that could have been
    triggered by responding to a query with inconsistent
    DNSSEC information, thereby facilitating a
    denial-of-service attack. [CVE-2016-9147, bsc#1018701,
    bsc#1018699]

  - Fix potential assertion failure that could have been
    triggered by DNS responses that contain unusually-formed
    DS resource records, facilitating a denial-of-service
    attack. [CVE-2016-9444, bsc#1018702, bsc#1018699]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9444.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170112-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2896e4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-bind-12936=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-bind-12936=1

SUSE Manager 2.1:zypper in -t patch sleman21-bind-12936=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-bind-12936=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-bind-12936=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-bind-12936=1

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-bind-12936=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-bind-12936=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-bind-12936=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"bind-libs-32bit-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"bind-libs-32bit-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-chrootenv-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-doc-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-libs-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bind-utils-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"bind-libs-32bit-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"bind-libs-32bit-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-chrootenv-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-doc-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-libs-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"bind-utils-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"bind-libs-32bit-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"bind-libs-32bit-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"bind-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"bind-chrootenv-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"bind-devel-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"bind-doc-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"bind-libs-9.9.6P1-0.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"bind-utils-9.9.6P1-0.36.1")) flag++;


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
