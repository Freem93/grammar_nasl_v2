#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49854);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/29 15:23:52 $");

  script_cve_id("CVE-2010-1797", "CVE-2010-2497", "CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2520", "CVE-2010-2527", "CVE-2010-2541", "CVE-2010-2805", "CVE-2010-2806", "CVE-2010-2807", "CVE-2010-2808");

  script_name(english:"SuSE 10 Security Update : freetype2 (ZYPP Patch Number 7121)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7121.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, reference:"freetype2-2.1.10-18.22.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"freetype2-devel-2.1.10-18.22.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"freetype2-32bit-2.1.10-18.22.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"freetype2-devel-32bit-2.1.10-18.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"freetype2-2.1.10-18.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"freetype2-devel-2.1.10-18.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"freetype2-32bit-2.1.10-18.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"freetype2-devel-32bit-2.1.10-18.22.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
