#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3068-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95710);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/27 20:33:26 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5573", "CVE-2016-5597");
  script_osvdb_id(145944, 145945, 145947, 145948, 145949, 145950);

  script_name(english:"SUSE SLES11 Security Update : java-1_7_0-ibm (SUSE-SU-2016:3068-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-ibm fixes the following issues :

  - Version update to 7.0-9.60 (bsc#1009280, bsc#992537)
    fixing the following CVE's: CVE-2016-5568,
    CVE-2016-5556, CVE-2016-5573, CVE-2016-5597,
    CVE-2016-5554, CVE-2016-5542

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5597.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163068-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13a6d589"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch
sleclo50sp3-java-1_7_0-ibm-12879=1

SUSE Manager Proxy 2.1:zypper in -t patch
slemap21-java-1_7_0-ibm-12879=1

SUSE Manager 2.1:zypper in -t patch sleman21-java-1_7_0-ibm-12879=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-java-1_7_0-ibm-12879=1

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-java-1_7_0-ibm-12879=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-java-1_7_0-ibm-12879=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-devel-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-jdbc-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-devel-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-jdbc-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.60-58.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.60-58.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-ibm");
}
