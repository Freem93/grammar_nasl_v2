#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34024);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-5240", "CVE-2008-1187", "CVE-2008-1196");

  script_name(english:"SuSE 10 Security Update : IBM Java 1.4.2 (ZYPP Patch Number 5465)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of IBM Java to 1.4.2 SR11 fixes various security 
problems :

  - Stack-based buffer overflow in Java Web Start
    (javaws.exe) allows remote attackers to execute
    arbitrary code via a crafted JNLP file. (CVE-2008-1196)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) allows remote attackers to cause a
    denial of service (JRE crash) and possibly execute
    arbitrary code via unknown vectors related to XSLT
    transforms. (CVE-2008-1187)

  - Visual truncation vulnerability in the Java Runtime
    Environment allows remote attackers to circumvent
    display of the untrusted-code warning banner by creating
    a window larger than the workstation screen.
    (CVE-2007-5240)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1196.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5465.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-ibm-1.4.2_sr11-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-ibm-devel-1.4.2_sr11-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr11-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr11-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_4_2-ibm-1.4.2_sr11-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_4_2-ibm-devel-1.4.2_sr11-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr11-0.6")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr11-0.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
