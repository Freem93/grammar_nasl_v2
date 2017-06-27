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
  script_id(65247);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2011-2728", "CVE-2012-5526", "CVE-2012-6329", "CVE-2013-1667");

  script_name(english:"SuSE 11.2 Security Update : Perl (SAT Patch Number 7439)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of Perl 5 fixes the following security issues :

  - fix rehash DoS [bnc#804415] [CVE-2013-1667]

  - improve CGI crlf escaping [bnc#789994] [CVE-2012-5526]

  - fix glob denial of service [bnc#796014] [CVE-2011-2728]

  - sanitize input in Maketext.pm [bnc#797060]
    [CVE-2012-6329]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2728.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1667.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7439.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki 5.1.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"perl-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"perl-base-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"perl-doc-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"perl-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"perl-32bit-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"perl-base-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"perl-doc-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"perl-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"perl-base-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"perl-doc-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"perl-32bit-5.10.0-64.61.61.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"perl-32bit-5.10.0-64.61.61.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
