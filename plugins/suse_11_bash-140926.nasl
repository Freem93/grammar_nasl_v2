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
  script_id(77958);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"SuSE 11.3 Security Update : bash (SAT Patch Number 9780)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The command-line shell 'bash' evaluates environment variables, which
allows the injection of characters and might be used to access files
on the system in some circumstances. (CVE-2014-7169)

Please note that this issue is different from a previously fixed
vulnerability tracked under CVE-2014-6271 and is less serious due to
the special, non-default system configuration that is needed to create
an exploitable situation.

To remove further exploitation potential we now limit the
function-in-environment variable to variables prefixed with
BASH_FUNC_. This hardening feature is work in progress and might be
improved in later updates.

Additionally, two other security issues have been fixed :

  - Nested HERE documents could lead to a crash of bash.
    (CVE-2014-7186)

  - Nesting of for loops could lead to a crash of bash.
    (CVE-2014-7187)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=898346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=898603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=898604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7187.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9780.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bash-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreadline5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreadline5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:readline-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"bash-3.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"bash-doc-3.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreadline5-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"readline-doc-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"bash-3.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"bash-doc-3.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreadline5-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreadline5-32bit-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"readline-doc-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"bash-3.2-147.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"bash-doc-3.2-147.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libreadline5-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"readline-doc-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libreadline5-32bit-5.2-147.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libreadline5-32bit-5.2-147.22.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
