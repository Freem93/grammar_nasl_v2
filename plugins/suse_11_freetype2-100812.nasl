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
  script_id(50905);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/11/29 15:23:52 $");

  script_cve_id("CVE-2010-1797", "CVE-2010-2497", "CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2520", "CVE-2010-2527", "CVE-2010-2541", "CVE-2010-2805", "CVE-2010-2806", "CVE-2010-2807", "CVE-2010-2808");

  script_name(english:"SuSE 11 / 11.1 Security Update : freetype2 (SAT Patch Numbers 2914 / 2919)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of freetype2 fixes several vulnerabilities that could lead
to remote system compromise by executing arbitrary code with user
privileges :

  - stack-based buffer overflow while processing CFF
    opcodes. (CVE-2010-1797)

  - integer underflow. (CVE-2010-2497)

  - invalid free. (CVE-2010-2498)

  - buffer overflow. (CVE-2010-2499)

  - integer overflow. (CVE-2010-2500)

  - heap buffer overflow. (CVE-2010-2519)

  - heap buffer overflow. (CVE-2010-2520)

  - buffer overflows in the freetype demo. (CVE-2010-2527)

  - buffer overflow in ftmulti demo program. (CVE-2010-2541)

  - improper bounds checking. (CVE-2010-2805)

  - improper bounds checking. (CVE-2010-2806)

  - improper type comparisons. (CVE-2010-2807)

  - memory corruption flaw by processing certain LWFN fonts.
    (CVE-2010-2808)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=628213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2499.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2520.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2808.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2914 / 2919 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:freetype2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:freetype2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:freetype2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"freetype2-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"freetype2-devel-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"freetype2-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"freetype2-32bit-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"freetype2-devel-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"freetype2-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"freetype2-devel-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"freetype2-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"freetype2-32bit-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"freetype2-devel-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"freetype2-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"freetype2-32bit-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"freetype2-32bit-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"freetype2-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"freetype2-32bit-2.3.7-25.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"freetype2-32bit-2.3.7-25.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
