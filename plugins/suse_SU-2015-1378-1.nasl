#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1378-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85399);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/09/29 14:15:33 $");

  script_cve_id("CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_bugtraq_id(74923, 75230, 75329, 75331);
  script_osvdb_id(122812, 123385, 123541, 123542);

  script_name(english:"SUSE SLED11 Security Update : libwmf (SUSE-SU-2015:1378-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libwmf was updated to fix four security issues.

These security issues were fixed :

  - CVE-2015-4588: Heap-based buffer overflow in the
    DecodeImage function allowed remote attackers to cause a
    denial of service (crash) or possibly execute arbitrary
    code via a crafted 'run-length count' in an image in a
    WMF file (bsc#933109).

  - CVE-2015-0848: Heap-based buffer overflow allowed remote
    attackers to cause a denial of service (crash) or
    possibly execute arbitrary code via a crafted BMP image
    (bsc#933109).

  - CVE-2015-4696: Use-after-free vulnerability allowed
    remote attackers to cause a denial of service (crash)
    via a crafted WMF file to the (1) wmf2gd or (2) wmf2eps
    command (bsc#936062).

  - CVE-2015-4695: meta.h allowed remote attackers to cause
    a denial of service (out-of-bounds read) via a crafted
    WMF file (bsc#936058).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/831299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4695.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4696.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151378-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8a84230"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-libwmf-12027=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-libwmf-12027=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-libwmf-12027=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-libwmf-12027=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-libwmf-12027=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libwmf-0.2.8.4-206.29.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libwmf-0.2.8.4-206.29.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libwmf-0.2.8.4-206.29.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libwmf-0.2.8.4-206.29.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwmf");
}
