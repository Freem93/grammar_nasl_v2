#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1258-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84876);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-5122", "CVE-2015-5123");
  script_bugtraq_id(75710, 75712);
  script_osvdb_id(124416, 124424);

  script_name(english:"SUSE SLED11 Security Update : flash-player (SUSE-SU-2015:1258-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"flash-player was updated to fix two security issues.

These security issues were fixed :

  - CVE-2015-5123: Use-after-free vulnerability in the
    BitmapData class in the ActionScript 3 (AS3)
    implementation in Adobe Flash Player allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via crafted Flash content
    that overrides a valueOf function (bsc#937752).

  - CVE-2015-5122: Use-after-free vulnerability in the
    DisplayObject class in the ActionScript 3 (AS3)
    implementation in Adobe Flash Player allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via crafted Flash content
    that leverages improper handling of the opaqueBackground
    property (bsc#937752).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5122.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5123.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151258-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdc66b11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-flash-player-12002=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-flash-player-12002=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash opaqueBackground Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");
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
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-gnome-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-kde4-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-gnome-11.2.202.491-0.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-kde4-11.2.202.491-0.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
