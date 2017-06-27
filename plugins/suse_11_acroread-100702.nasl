#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50882);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2014/10/24 10:42:17 $");

  script_cve_id("CVE-2010-1240", "CVE-2010-1285", "CVE-2010-1295", "CVE-2010-1297", "CVE-2010-2168", "CVE-2010-2201", "CVE-2010-2202", "CVE-2010-2203", "CVE-2010-2204", "CVE-2010-2205", "CVE-2010-2206", "CVE-2010-2207", "CVE-2010-2208", "CVE-2010-2209", "CVE-2010-2210", "CVE-2010-2211", "CVE-2010-2212");

  script_name(english:"SuSE 11 / 11.1 Security Update : acroread (SAT Patch Numbers 2639 / 2640)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted PDF documents could crash acroread or lead to
execution of arbitrary code. The fixed security issues have been
tracked as :

  - CVE-2010-1297

  - CVE-2010-1240

  - CVE-2010-1285

  - CVE-2010-1295

  - CVE-2010-2168

  - CVE-2010-2201

  - CVE-2010-2202

  - CVE-2010-2203

  - CVE-2010-2204

  - CVE-2010-2205

  - CVE-2010-2206

  - CVE-2010-2207

  - CVE-2010-2208

  - CVE-2010-2209

  - CVE-2010-2210

  - CVE-2010-2211

  - CVE-2010-2212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1285.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1295.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1297.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2201.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2205.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2208.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2210.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2211.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2212.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2639 / 2640 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "newfunction" Invalid Pointer Use');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"acroread-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"acroread-cmaps-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"acroread-fonts-ja-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"acroread-fonts-ko-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"acroread-fonts-zh_CN-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"acroread-fonts-zh_TW-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"acroread-cmaps-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"acroread-fonts-ja-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"acroread-fonts-ko-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"acroread-fonts-zh_CN-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"acroread-fonts-zh_TW-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-cmaps-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-ja-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-ko-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-zh_CN-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-zh_TW-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-cmaps-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-ja-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-ko-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-zh_CN-9.3.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-zh_TW-9.3.3-0.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
