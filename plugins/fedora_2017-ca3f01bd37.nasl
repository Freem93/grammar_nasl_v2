#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-ca3f01bd37.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97683);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_xref(name:"FEDORA", value:"2017-ca3f01bd37");

  script_name(english:"Fedora 25 : php-pear-PHP-CodeSniffer (2017-ca3f01bd37)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 2.8.1**

  - This release contains a fix for a security advisory
    related to the improper handling of shell commands

  - Uses of shell_exec() and exec() were not escaping
    filenames and configuration settings in most cases

  - A properly crafted filename or configuration option
    would allow for arbitrary code execution when using some
    features

  - All users are encouraged to upgrade to this version,
    especially if you are checking 3rd-party code

  - e.g., you run PHPCS over libraries that you did not
    write

  - e.g., you provide a web service that runs PHPCS over
    user-uploaded files or 3rd-party repositories

  - e.g., you allow external tool paths to be set by
    user-defined values

  - If you are unable to upgrade but you check 3rd-party
    code, ensure you are not using the following features :

  - The diff report

  - The notify-send report

  - The Generic.PHP.Syntax sniff

  - The Generic.Debug.CSSLint sniff

  - The Generic.Debug.ClosureLinter sniff

  - The Generic.Debug.JSHint sniff

  - The Squiz.Debug.JSLint sniff

  - The Squiz.Debug.JavaScriptLint sniff

  - The Zend.Debug.CodeAnalyzer sniff

  - Thanks to Klaus Purer for the report

  - The PHP-supplied T_COALESCE_EQUAL token has been
    replicated for PHP versions before 7.2

  - PEAR.Functions.FunctionDeclaration now reports an error
    for blank lines found inside a function declaration

  - PEAR.Functions.FunctionDeclaration no longer reports
    indent errors for blank lines in a function declaration

  - Squiz.Functions.MultiLineFunctionDeclaration no longer
    reports errors for blank lines in a function declaration

  - It would previously report that only one argument is
    allowed per line

  - Squiz.Commenting.FunctionComment now corrects multi-line
    param comment padding more accurately

  - Squiz.Commenting.FunctionComment now properly fixes
    pipe-separated param types

  - Squiz.Commenting.FunctionComment now works correctly
    when function return types also contain a comment

  - Thanks to Juliette Reinders Folmer for the patch

  - Squiz.ControlStructures.InlineIfDeclaration now supports
    the elvis operator

  - As this is not a real PHP operator, it enforces no
    spaces between ? and : when the THEN statement is empty

  - Squiz.ControlStructures.InlineIfDeclaration is now able
    to fix the spacing errors it reports

  - Fixed bug #1340 : STDIN file contents not being
    populated in some cases

  - Thanks to David Bi?ovec for the patch

  - Fixed bug #1344 :
    PEAR.Functions.FunctionCallSignatureSniff throws error
    for blank comment lines

  - Fixed bug #1347 : PSR2.Methods.FunctionCallSignature
    strips some comments during fixing

  - Thanks to Algirdas Gurevicius for the patch

  - Fixed bug #1349 :
    Squiz.Strings.DoubleQuoteUsage.NotRequired message is
    badly formatted when string contains a CR newline char

  - Thanks to Algirdas Gurevicius for the patch

  - Fixed bug #1350 : Invalid
    Squiz.Formatting.OperatorBracket error when using
    namespaces

  - Fixed bug #1369 : Empty line in multi-line function
    declaration cause infinite loop

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-ca3f01bd37"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear-PHP-CodeSniffer package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-PHP-CodeSniffer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"php-pear-PHP-CodeSniffer-2.8.1-1.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear-PHP-CodeSniffer");
}
