#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2170-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87196);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-1606", "CVE-2015-1607");
  script_bugtraq_id(72609, 72610);
  script_osvdb_id(118467, 118468);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : gpg2 (SUSE-SU-2015:2170-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gpg2 fixes the following issues :

  - Fix cve-2015-1606 (bsc#918089)

  - Invalid memory read using a garbled keyring

  -
    0001-Gpg-prevent-an-invalid-memory-read-using-a-garbled-
    k.patch

  - Fix cve-2015-1607 (bsc#918090)

  - Memcpy with overlapping ranges

  -
    0001-Use-inline-functions-to-convert-buffer-data-to-scal
    a.patch

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1606.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1607.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152170-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f2c22a2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-gpg2-12240=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-gpg2-12240=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-gpg2-12240=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-gpg2-12240=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-gpg2-12240=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-gpg2-12240=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-gpg2-12240=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gpg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gpg2-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"gpg2-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"gpg2-lang-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"gpg2-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"gpg2-lang-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"gpg2-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"gpg2-lang-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"gpg2-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"gpg2-lang-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"gpg2-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"gpg2-lang-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"gpg2-2.0.9-25.33.41.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"gpg2-lang-2.0.9-25.33.41.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gpg2");
}
