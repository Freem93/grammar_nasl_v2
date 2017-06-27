#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2166-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87180);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-0204", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-2625", "CVE-2015-2808", "CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4810", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4871", "CVE-2015-4872", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4902", "CVE-2015-4903", "CVE-2015-4911", "CVE-2015-5006");
  script_bugtraq_id(71936, 73684, 74072, 74083, 74094, 74104, 74111, 74119, 74141, 74147, 75895);
  script_osvdb_id(15435, 116794, 117855, 120702, 120705, 120709, 120710, 120712, 120713, 120714, 124639, 129119, 129121, 129122, 129123, 129124, 129125, 129128, 129129, 129130, 129131, 129132, 129133, 129134, 129135, 129136, 129137, 129138, 129139, 129140, 130241);

  script_name(english:"SUSE SLES11 Security Update : java-1_6_0-ibm (SUSE-SU-2015:2166-1) (Bar Mitzvah) (FREAK)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_6_0-ibm fixes the following issues :

  - Version update to 6.0-16.15 bsc#955131: CVE-2015-4734
    CVE-2015-4803 CVE-2015-4805 CVE-2015-4806 CVE-2015-4810
    CVE-2015-4835 CVE-2015-4840 CVE-2015-4842 CVE-2015-4843
    CVE-2015-4844 CVE-2015-4860 CVE-2015-4871 CVE-2015-4872
    CVE-2015-4882 CVE-2015-4883 CVE-2015-4893 CVE-2015-4902
    CVE-2015-4903 CVE-2015-4911 CVE-2015-5006

    CVE-2015-2808 CVE-2015-2625 CVE-2015-0491 CVE-2015-0459
    CVE-2015-0469 CVE-2015-0458 CVE-2015-0480 CVE-2015-0488
    CVE-2015-0478 CVE-2015-0477 CVE-2015-0204

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4810.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4882.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4883.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4902.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4911.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5006.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152166-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e2f824b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-java-1_6_0-ibm-1538=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-java-1_6_0-ibm-1538=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-java-1_6_0-ibm-1538=1

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-java-1_6_0-ibm-1538=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_6_0-ibm-alsa-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_6_0-ibm-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_6_0-ibm-fonts-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_6_0-ibm-jdbc-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_6_0-ibm-alsa-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_6_0-ibm-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_6_0-ibm-devel-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_6_0-ibm-fonts-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_6_0-ibm-jdbc-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0_sr16.15-46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr16.15-46.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-ibm");
}