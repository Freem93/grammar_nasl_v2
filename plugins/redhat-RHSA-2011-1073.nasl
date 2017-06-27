#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1073. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55646);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2008-5374");
  script_bugtraq_id(32733);
  script_xref(name:"RHSA", value:"2011:1073");

  script_name(english:"RHEL 5 : bash (RHSA-2011:1073)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated bash package that fixes one security issue, several bugs,
and adds one enhancement is now available for Red Hat Enterprise Linux
5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Bash is the default shell for Red Hat Enterprise Linux.

It was found that certain scripts bundled with the Bash documentation
created temporary files in an insecure way. A malicious, local user
could use this flaw to conduct a symbolic link attack, allowing them
to overwrite the contents of arbitrary files accessible to the victim
running the scripts. (CVE-2008-5374)

This update fixes the following bugs :

* When using the source builtin at location '.', occasionally, bash
opted to preserve internal consistency and abort scripts. This caused
bash to abort scripts that assigned values to read-only variables.
This is now fixed to ensure that such scripts are now executed as
written and not aborted. (BZ#448508)

* When the tab key was pressed for auto-completion options for the
typed text, the cursor moved to an unexpected position on a previous
line if the prompt contained characters that cannot be viewed and a
'\]'. This is now fixed to retain the cursor at the expected position
at the end of the target line after autocomplete options correctly
display. (BZ#463880)

* Bash attempted to interpret the NOBITS .dynamic section of the ELF
header. This resulted in a '^D: bad ELF interpreter: No such file or
directory' message. This is fixed to ensure that the invalid '^D' does
not appear in the error message. (BZ#484809)

* The $RANDOM variable in Bash carried over values from a previous
execution for later jobs. This is fixed and the $RANDOM variable
generates a new random number for each use. (BZ#492908)

* When Bash ran a shell script with an embedded null character, bash's
source builtin parsed the script incorrectly. This is fixed and bash's
source builtin correctly parses shell script null characters.
(BZ#503701)

* The bash manual page for 'trap' did not mention that signals ignored
upon entry cannot be listed later. The manual page was updated for
this update and now specifically notes that 'Signals ignored upon
entry to the shell cannot be trapped, reset or listed'. (BZ#504904)

* Bash's readline incorrectly displayed additional text when resizing
the terminal window when text spanned more than one line, which caused
incorrect display output. This is now fixed to ensure that text in
more than one line in a resized window displays as expected.
(BZ#525474)

* Previously, bash incorrectly displayed 'Broken pipe' messages for
builtins like 'echo' and 'printf' when output did not succeed due to
EPIPE. This is fixed to ensure that the unnecessary 'Broken pipe'
messages no longer display. (BZ#546529)

* Inserts with the repeat function were not possible after a deletion
in vi-mode. This has been corrected and, with this update, the repeat
function works as expected after a deletion. (BZ#575076)

* In some situations, bash incorrectly appended '/' to files instead
of just directories during tab-completion, causing incorrect
auto-completions. This is fixed and auto-complete appends '/' only to
directories. (BZ#583919)

* Bash had a memory leak in the 'read' builtin when the number of
fields being read was not equal to the number of variables passed as
arguments, causing a shell script crash. This is fixed to prevent a
memory leak and shell script crash. (BZ#618393)

* /usr/share/doc/bash-3.2/loadables in the bash package contained
source files which would not build due to missing C header files. With
this update, the unusable (and unbuildable) source files were removed
from the package. (BZ#663656)

This update also adds the following enhancement :

* The system-wide '/etc/bash.bash_logout' bash logout file is now
enabled. This allows administrators to write system-wide logout
actions for all users. (BZ#592979)

Users of bash are advised to upgrade to this updated package, which
contains backported patches to resolve these issues and add this
enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5374.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1073.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bash package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1073";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bash-3.2-32.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bash-3.2-32.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bash-3.2-32.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");
  }
}
