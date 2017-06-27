#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61088);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2008-5374");

  script_name(english:"Scientific Linux Security Update : bash on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bash is the default shell for Scientific Linux.

It was found that certain scripts bundled with the Bash documentation
created temporary files in an insecure way. A malicious, local user
could use this flaw to conduct a symbolic link attack, allowing them
to overwrite the contents of arbitrary files accessible to the victim
running the scripts. (CVE-2008-5374)

This update fixes the following bugs :

  - When using the source builtin at location '.',
    occasionally, bash opted to preserve internal
    consistency and abort scripts. This caused bash to abort
    scripts that assigned values to read-only variables.
    This is now fixed to ensure that such scripts are now
    executed as written and not aborted.

  - When the tab key was pressed for auto-completion options
    for the typed text, the cursor moved to an unexpected
    position on a previous line if the prompt contained
    characters that cannot be viewed and a '\]'. This is now
    fixed to retain the cursor at the expected position at
    the end of the target line after autocomplete options
    correctly display.

  - Bash attempted to interpret the NOBITS .dynamic section
    of the ELF header. This resulted in a '^D: bad ELF
    interpreter: No such file or directory' message. This is
    fixed to ensure that the invalid '^D' does not appear in
    the error message.

  - The $RANDOM variable in Bash carried over values from a
    previous execution for later jobs. This is fixed and the
    $RANDOM variable generates a new random number for each
    use.

  - When Bash ran a shell script with an embedded null
    character, bash's source builtin parsed the script
    incorrectly. This is fixed and bash's source builtin
    correctly parses shell script null characters.

  - The bash manual page for 'trap' did not mention that
    signals ignored upon entry cannot be listed later. The
    manual page was updated for this update and now
    specifically notes that 'Signals ignored upon entry to
    the shell cannot be trapped, reset or listed'.

  - Bash's readline incorrectly displayed additional text
    when resizing the terminal window when text spanned more
    than one line, which caused incorrect display output.
    This is now fixed to ensure that text in more than one
    line in a resized window displays as expected.

  - Previously, bash incorrectly displayed 'Broken pipe'
    messages for builtins like 'echo' and 'printf' when
    output did not succeed due to EPIPE. This is fixed to
    ensure that the unnecessary 'Broken pipe' messages no
    longer display.

  - Inserts with the repeat function were not possible after
    a deletion in vi-mode. This has been corrected and, with
    this update, the repeat function works as expected after
    a deletion.

  - In some situations, bash incorrectly appended '/' to
    files instead of just directories during tab-completion,
    causing incorrect auto-completions. This is fixed and
    auto-complete appends '/' only to directories.

  - Bash had a memory leak in the 'read' builtin when the
    number of fields being read was not equal to the number
    of variables passed as arguments, causing a shell script
    crash. This is fixed to prevent a memory leak and shell
    script crash.

  - /usr/share/doc/bash-3.2/loadables in the bash package
    contained source files which would not build due to
    missing C header files. With this update, the unusable
    (and unbuildable) source files were removed from the
    package.

This update also adds the following enhancement :

  - The system-wide '/etc/bash.bash_logout' bash logout file
    is now enabled. This allows administrators to write
    system-wide logout actions for all users.

Users of bash are advised to upgrade to this updated package, which
contains backported patches to resolve these issues and add this
enhancement."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=673
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5047e362"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bash package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"bash-3.2-32.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
