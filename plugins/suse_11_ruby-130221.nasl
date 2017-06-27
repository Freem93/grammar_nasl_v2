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
  script_id(65248);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:04 $");

  script_cve_id("CVE-2012-4464", "CVE-2012-4466", "CVE-2012-4522");

  script_name(english:"SuSE 11.2 Security Update : ruby (SAT Patch Number 7386)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ruby interpreter received a fix for a security issue :

  - Ruby's $SAFE mechanism enables untrusted user codes to
    run in $SAFE >= 4 mode. This is a kind of sandboxing so
    some operations are restricted in that mode to protect
    other data outside the sandbox. (CVE-2012-4466)

    The problem found was around this mechanism.
    Exception#to_s, NameError#to_s, and name_err_mesg_to_s()
    interpreter-internal API was not correctly handling the
    $SAFE bits so a String object which is not tainted can
    destructively be marked as tainted using them. By using
    this an untrusted code in a sandbox can modify a
    formerly-untainted string destructively.

    http://www.ruby-lang.org/en/news/2012/10/12/cve-2012-446
    4-cve-2012-4466/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4464.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4522.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7386.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"ruby-1.8.7.p357-0.9.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"ruby-1.8.7.p357-0.9.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"ruby-1.8.7.p357-0.9.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"ruby-doc-html-1.8.7.p357-0.9.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"ruby-tk-1.8.7.p357-0.9.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
