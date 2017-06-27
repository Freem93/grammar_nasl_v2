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
  script_id(57430);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/01/15 16:41:30 $");

  script_cve_id("CVE-2011-1526", "CVE-2011-4862");

  script_name(english:"SuSE 11.1 Security Update : Kerberos 5 (SAT Patch Number 5594)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of krb5 fixes two security issues.

  - A remote code execution in the kerberized telnet daemon
    was fixed. (This only affects the ktelnetd from the
    krb5-appl RPM, not the regular telnetd supplied by
    SUSE.). (CVE-2011-4862)

  - / MITKRB5-SA-2011-005: Fixed krb5 ftpd unauthorized file
    access problems. (CVE-2011-1526)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4862.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5594.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-apps-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-apps-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"krb5-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"krb5-client-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"krb5-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"krb5-client-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"krb5-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"krb5-apps-clients-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"krb5-apps-servers-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"krb5-client-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"krb5-server-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"krb5-32bit-1.6.3-133.48.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.48.48.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
