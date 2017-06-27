#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1064-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84207);
  script_version("$Revision: 2.15 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2014-5333", "CVE-2015-3096", "CVE-2015-3098", "CVE-2015-3099", "CVE-2015-3100", "CVE-2015-3102", "CVE-2015-3103", "CVE-2015-3104", "CVE-2015-3105", "CVE-2015-3106", "CVE-2015-3107", "CVE-2015-3108");
  script_bugtraq_id(69320, 75080, 75081, 75084, 75085, 75086, 75087, 75088);
  script_osvdb_id(108828, 123020, 123021, 123022, 123023, 123024, 123025, 123026, 123028, 123029, 123030, 123032);

  script_name(english:"SUSE SLED11 Security Update : flash-player (SUSE-SU-2015:1064-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe Flash Player was updated to 11.2.202.466 to fix multiple
security issues.

The following vulnerabilities were fixed :

CVE-2015-3096: bypass for CVE-2014-5333

CVE-2015-3098: vulnerabilities that could be exploited to bypass the
same-origin-policy and lead to information disclosure

CVE-2015-3099: vulnerabilities that could be exploited to bypass the
same-origin-policy and lead to information disclosure

CVE-2015-3100: stack overflow vulnerability that could lead to code
execution

CVE-2015-3102: vulnerabilities that could be exploited to bypass the
same-origin-policy and lead to information disclosure

CVE-2015-3103: use-after-free vulnerabilities that could lead to code
execution

CVE-2015-3104: integer overflow vulnerability that could lead to code
execution

CVE-2015-3105: memory corruption vulnerability that could lead to code
execution

CVE-2015-3106: use-after-free vulnerabilities that could lead to code
execution

CVE-2015-3107: use-after-free vulnerabilities that could lead to code
execution

CVE-2015-3108: memory leak vulnerability that could be used to bypass
ASLR

More information can be found on: <a
href='https://helpx.adobe.com/security/products/flash-player/apsb15-11
.html'>https://helpx.adobe.com/security/products/flash-player/apsb15-1
1.html</a>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934088"
  );
  # https://download.suse.com/patch/finder/?keywords=54458c18e1bae698ba1e29aba887242a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3593910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb15-11.html'"
  );
  # https://helpx.adobe.com/security/products/flash-player/apsb15-11.html</a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16f4c888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3099.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3108.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151064-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27ba6106"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-flash-player=10762

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Drawing Fill Shader Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");
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
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-11.2.202.466-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.466-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.466-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-11.2.202.466-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-gnome-11.2.202.466-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-kde4-11.2.202.466-0.6.1")) flag++;


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
