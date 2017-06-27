#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2236-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87317);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-8045", "CVE-2015-8047", "CVE-2015-8048", "CVE-2015-8049", "CVE-2015-8050", "CVE-2015-8055", "CVE-2015-8056", "CVE-2015-8057", "CVE-2015-8058", "CVE-2015-8059", "CVE-2015-8060", "CVE-2015-8061", "CVE-2015-8062", "CVE-2015-8063", "CVE-2015-8064", "CVE-2015-8065", "CVE-2015-8066", "CVE-2015-8067", "CVE-2015-8068", "CVE-2015-8069", "CVE-2015-8070", "CVE-2015-8071", "CVE-2015-8401", "CVE-2015-8402", "CVE-2015-8403", "CVE-2015-8404", "CVE-2015-8405", "CVE-2015-8406", "CVE-2015-8407", "CVE-2015-8408", "CVE-2015-8409", "CVE-2015-8410", "CVE-2015-8411", "CVE-2015-8412", "CVE-2015-8413", "CVE-2015-8414", "CVE-2015-8415", "CVE-2015-8416", "CVE-2015-8417", "CVE-2015-8418", "CVE-2015-8419", "CVE-2015-8420", "CVE-2015-8421", "CVE-2015-8422", "CVE-2015-8423", "CVE-2015-8424", "CVE-2015-8425", "CVE-2015-8426", "CVE-2015-8427", "CVE-2015-8428", "CVE-2015-8429", "CVE-2015-8430", "CVE-2015-8431", "CVE-2015-8432", "CVE-2015-8433", "CVE-2015-8434", "CVE-2015-8435", "CVE-2015-8436", "CVE-2015-8437", "CVE-2015-8438", "CVE-2015-8439", "CVE-2015-8440", "CVE-2015-8441", "CVE-2015-8442", "CVE-2015-8443", "CVE-2015-8444", "CVE-2015-8445", "CVE-2015-8446", "CVE-2015-8447", "CVE-2015-8448", "CVE-2015-8449", "CVE-2015-8450", "CVE-2015-8451", "CVE-2015-8452", "CVE-2015-8453", "CVE-2015-8454", "CVE-2015-8455");
  script_osvdb_id(131208, 131209, 131210, 131211, 131212, 131213, 131214, 131215, 131216, 131217, 131218, 131219, 131220, 131221, 131222, 131223, 131224, 131225, 131226, 131227, 131228, 131229, 131230, 131231, 131232, 131233, 131234, 131235, 131236, 131237, 131238, 131239, 131240, 131241, 131242, 131243, 131244, 131245, 131246, 131247, 131248, 131249, 131250, 131251, 131252, 131253, 131254, 131255, 131256, 131257, 131258, 131259, 131260, 131261, 131262, 131264, 131265, 131266, 131267, 131268, 131269, 131270, 131271, 131272, 131273, 131274, 131275, 131276, 131277, 131278, 131279, 131280, 131281, 131282, 131463, 131464, 131465);

  script_name(english:"SUSE SLED11 Security Update : flash-player (SUSE-SU-2015:2236-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flash-player to version 11.2.202.554 fixes the
following security issues in Adobe security advisory APSB15-32.

  - These updates resolve heap buffer overflow
    vulnerabilities that could lead to code execution
    (CVE-2015-8438, CVE-2015-8446).

  - These updates resolve memory corruption vulnerabilities
    that could lead to code execution (CVE-2015-8444,
    CVE-2015-8443, CVE-2015-8417, CVE-2015-8416,
    CVE-2015-8451, CVE-2015-8047, CVE-2015-8455,
    CVE-2015-8045, CVE-2015-8418, CVE-2015-8060,
    CVE-2015-8419, CVE-2015-8408).

  - These updates resolve security bypass vulnerabilities
    (CVE-2015-8453, CVE-2015-8440, CVE-2015-8409).

  - These updates resolve a stack overflow vulnerability
    that could lead to code execution (CVE-2015-8407).

  - These updates resolve a type confusion vulnerability
    that could lead to code execution (CVE-2015-8439).

  - These updates resolve an integer overflow vulnerability
    that could lead to code execution (CVE-2015-8445).

  - These updates resolve a buffer overflow vulnerability
    that could lead to code execution (CVE-2015-8415)

  - These updates resolve use-after-free vulnerabilities
    that could lead to code execution (CVE-2015-8050,
    CVE-2015-8049, CVE-2015-8437, CVE-2015-8450,
    CVE-2015-8449, CVE-2015-8448, CVE-2015-8436,
    CVE-2015-8452, CVE-2015-8048, CVE-2015-8413,
    CVE-2015-8412, CVE-2015-8410, CVE-2015-8411,
    CVE-2015-8424, CVE-2015-8422, CVE-2015-8420,
    CVE-2015-8421, CVE-2015-8423, CVE-2015-8425,
    CVE-2015-8433, CVE-2015-8432, CVE-2015-8431,
    CVE-2015-8426, CVE-2015-8430, CVE-2015-8427,
    CVE-2015-8428, CVE-2015-8429, CVE-2015-8434,
    CVE-2015-8435, CVE-2015-8414, CVE-2015-8454,
    CVE-2015-8059, CVE-2015-8058, CVE-2015-8055,
    CVE-2015-8057, CVE-2015-8056, CVE-2015-8061,
    CVE-2015-8067, CVE-2015-8066, CVE-2015-8062,
    CVE-2015-8068, CVE-2015-8064, CVE-2015-8065,
    CVE-2015-8063, CVE-2015-8405, CVE-2015-8404,
    CVE-2015-8402, CVE-2015-8403, CVE-2015-8071,
    CVE-2015-8401, CVE-2015-8406, CVE-2015-8069,
    CVE-2015-8070, CVE-2015-8441, CVE-2015-8442,
    CVE-2015-8447).

Please also see
https://helpx.adobe.com/security/products/flash-player/apsb15-32.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8058.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8068.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8403.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8406.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8407.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8408.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8413.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8414.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8431.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8436.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8437.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8443.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8445.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8447.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8448.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8449.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8450.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8452.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8455.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152236-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3aa385c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-flash-player-12254=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-flash-player-12254=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");
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
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-gnome-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-kde4-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-gnome-11.2.202.554-0.29.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-kde4-11.2.202.554-0.29.1")) flag++;


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
