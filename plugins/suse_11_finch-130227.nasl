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
  script_id(65024);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:41:53 $");

  script_cve_id("CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");

  script_name(english:"SuSE 11.2 Security Update : pidgin (SAT Patch Number 7429)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pidgin was updated to fix 4 security issues :

  - Fixed a crash when receiving UPnP responses with
    abnormally long values. (CVE-2013-0274, bnc#804742)

  - Fixed a crash in Sametime protocol when a malicious
    server sends us an abnormally long user ID.
    (CVE-2013-0273, bnc#804742)

  - Fixed a bug where the MXit server or a man-in-the-middle
    could potentially send specially crafted data that could
    overflow a buffer and lead to a crash or remote code
    execution. (CVE-2013-0272, bnc#804742)

  - Fixed a bug where a remote MXit user could possibly
    specify a local file path to be written to.
    (CVE-2013-0271, bnc#804742)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0274.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7429.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"finch-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libpurple-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libpurple-lang-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libpurple-meanwhile-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libpurple-tcl-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"pidgin-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"finch-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libpurple-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libpurple-lang-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libpurple-meanwhile-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libpurple-tcl-2.6.6-0.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"pidgin-2.6.6-0.19.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
