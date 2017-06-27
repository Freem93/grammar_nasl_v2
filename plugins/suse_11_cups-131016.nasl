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
  script_id(70842);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:30:41 $");

  script_cve_id("CVE-2012-5519");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : CUPS (SAT Patch Numbers 8436 / 8437)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issue has been fixed in the CUPS print daemon
CVE-2012-5519: The patch adds better default protection against misuse
of privileges by normal users who have been specifically allowed by
root to do cupsd configuration changes

The new ConfigurationChangeRestriction cupsd.conf directive specifies
the level of restriction for cupsd.conf changes that happen via
HTTP/IPP requests to the running cupsd (e.g. via CUPS web interface or
via the cupsctl command).

By default certain cupsd.conf directives that deal with filenames,
paths, and users can no longer be changed via requests to the running
cupsd but only by manual editing the cupsd.conf file and its default
file permissions permit only root to write the cupsd.conf file.

Those directives are: ConfigurationChangeRestriction, AccessLog,
BrowseLDAPCACertFile, CacheDir, ConfigFilePerm, DataDir, DocumentRoot,
ErrorLog, FileDevice, FontPath, Group, LogFilePerm, PageLog, Printcap,
PrintcapFormat, PrintcapGUI, RemoteRoot, RequestRoot, ServerBin,
ServerCertificate, ServerKey, ServerRoot, StateDir, SystemGroup,
SystemGroupAuthKey, TempDir, User.

The default group of users who are allowed to do cupsd configuration
changes via requests to the running cupsd (i.e. the SystemGroup
directive in cupsd.conf) is set to 'root' only.

Additionally the following bug has been fixed :

  - strip trailing '@REALM' from username for Kerberos
    authentication (CUPS STR#3972 bnc#827109)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5519.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8436 / 8437 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:cups-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"cups-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"cups-client-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"cups-libs-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"cups-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"cups-client-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"cups-libs-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"cups-libs-32bit-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"cups-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"cups-client-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"cups-libs-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"cups-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"cups-client-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"cups-libs-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"cups-libs-32bit-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"cups-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"cups-client-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"cups-libs-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"cups-libs-32bit-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"cups-libs-32bit-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"cups-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"cups-client-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"cups-libs-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"cups-libs-32bit-1.3.9-8.46.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"cups-libs-32bit-1.3.9-8.46.48.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
