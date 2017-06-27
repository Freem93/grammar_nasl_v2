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
  script_id(64098);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/18 11:46:15 $");

  script_cve_id("CVE-2012-1530", "CVE-2013-0601", "CVE-2013-0602", "CVE-2013-0603", "CVE-2013-0604", "CVE-2013-0605", "CVE-2013-0606", "CVE-2013-0607", "CVE-2013-0608", "CVE-2013-0609", "CVE-2013-0610", "CVE-2013-0611", "CVE-2013-0612", "CVE-2013-0613", "CVE-2013-0614", "CVE-2013-0615", "CVE-2013-0616", "CVE-2013-0617", "CVE-2013-0618", "CVE-2013-0619", "CVE-2013-0620", "CVE-2013-0621", "CVE-2013-0622", "CVE-2013-0623", "CVE-2013-0624", "CVE-2013-0626", "CVE-2013-0627");

  script_name(english:"SuSE 11.2 Security Update : Acrobat Reader (SAT Patch Number 7230)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Acrobat Reader was updated to 9.5.3 to fix various bugs and security
issues.

More information can be found at
http://www.adobe.com/support/security/bulletins/apsb13-02.html

The resolved security issues are CVE-2012-1530 / CVE-2013-0601 /
CVE-2013-0602 / CVE-2013-0603 / CVE-2013-0604 / CVE-2013-0605 /
CVE-2013-0606 / CVE-2013-0607 / CVE-2013-0608 / CVE-2013-0609 /
CVE-2013-0610 / CVE-2013-0611 / CVE-2013-0612 / CVE-2013-0613 /
CVE-2013-0614 / CVE-2013-0615 / CVE-2013-0616 / CVE-2013-0617 /
CVE-2013-0618 / CVE-2013-0619 / CVE-2013-0620 / CVE-2013-0621 /
CVE-2013-0622 / CVE-2013-0623 / CVE-2013-0624 / CVE-2013-0626 /
CVE-2013-0627."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0602.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0603.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0604.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0605.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0606.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0607.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0609.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0610.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0611.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0612.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0614.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0616.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0617.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0618.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0620.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0622.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0623.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0624.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0626.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0627.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7230.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-9.5.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-cmaps-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-ja-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-ko-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-zh_CN-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"acroread-fonts-zh_TW-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-cmaps-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-ja-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-ko-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-zh_CN-9.4.6-0.4.2.4")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"acroread-fonts-zh_TW-9.4.6-0.4.2.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
