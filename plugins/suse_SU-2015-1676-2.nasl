#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1676-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86289);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2015-3813", "CVE-2015-4652", "CVE-2015-6241", "CVE-2015-6242", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6247", "CVE-2015-6248", "CVE-2015-6249");
  script_bugtraq_id(74633, 75316);
  script_osvdb_id(122091, 123439, 126172, 126173, 126174, 126175, 126176, 126177, 126178, 126179, 126180);

  script_name(english:"SUSE SLED11 Security Update : wireshark (SUSE-SU-2015:1676-2)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark has been updated to 1.12.7. (FATE#319388)

The following vulnerabilities have been fixed :

  - Wireshark could crash when adding an item to the
    protocol tree. wnpa-sec-2015-21 CVE-2015-6241

  - Wireshark could attempt to free invalid memory.
    wnpa-sec-2015-22 CVE-2015-6242

  - Wireshark could crash when searching for a protocol
    dissector. wnpa-sec-2015-23 CVE-2015-6243

  - The ZigBee dissector could crash. wnpa-sec-2015-24
    CVE-2015-6244

  - The GSM RLC/MAC dissector could go into an infinite
    loop. wnpa-sec-2015-25 CVE-2015-6245

  - The WaveAgent dissector could crash. wnpa-sec-2015-26
    CVE-2015-6246

  - The OpenFlow dissector could go into an infinite loop.
    wnpa-sec-2015-27 CVE-2015-6247

  - Wireshark could crash due to invalid ptvcursor length
    checking. wnpa-sec-2015-28 CVE-2015-6248

  - The WCCP dissector could crash. wnpa-sec-2015-29
    CVE-2015-6249

  - Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.12.7
    .html

Also a fix from 1.12.6 in GSM DTAP was backported. (bnc#935158
CVE-2015-4652)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4652.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6241.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6245.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6246.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6247.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6248.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6249.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151676-2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa555031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.7.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-wireshark-1127-12112=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-wireshark-1127-12112=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-wireshark-1127-12112=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-wireshark-1127-12112=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");
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
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"wireshark-1.12.7-0.5.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"wireshark-1.12.7-0.5.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"wireshark-1.12.7-0.5.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"wireshark-1.12.7-0.5.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
