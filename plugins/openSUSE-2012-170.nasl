#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-170.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74572);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-1095");

  script_name(english:"openSUSE Security Update : osc (openSUSE-SU-2012:0400-1)");
  script_summary(english:"Check for the openSUSE-2012-170 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of osc to 0.134.1 provides the following changes :

  - adding unlock command

  - maintenance_incident requests get created with source
    revision of package

  - Enables new maintenance submissions for new OBS 2.3
    maintenance model

  - Fixes srcmd5 revisions in submit request, when link
    target != submission target

  - patchinfo call can work without checked out copy now

  - use qemu as fallback for building not directly supported
    architectures

  - 'results --watch' option to watch build results until
    they finished building

  - fixes injection of terminal control chars
    (bnc#749335)(CVE-2012-1095)

  - support dryrun of branching to preview the expected
    result. 'osc sm' is doing this now by default.

  - maintenance requests accept package lists as source and
    target incidents to be merged in

  - add 'setincident' command to 'request' to re-direct a
    maintenance request

  - ask user to create 'maintenance incident' request when
    submit request is failing at release project

  - 'osc my patchinfos' is showing patchinfos where any open
    bug is assigned to user

  - 'osc my' or 'osc my work' is including assigned
    patchinfos

  - 'osc branch --maintenance' is creating setups for
    maintenance

  - removed debug code lead to warning message (fix by
    Marcus_H)

  - add --meta option also to 'list', 'cat' and 'less'
    commands

  - project checkout is skipping packages linking to project
    local packages by default

  - add --keep-link option to copypac command

  - source validators are not called by default anymore :

  - support source services using OBS project or package
    name

  - support updateing _patchinfo file with new issues just
    by calling 'osc patchinfo' again

  - branch --add-repositories can be used to add repos from
    source project to target project

  - branch --extend-package-names can be used to do mbranch
    like branch of a single package

  - branch --new-package can be used to do branch from a not
    yet existing package (to define later submit target)

  - show declined requests which created by user"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-03/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749335"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected osc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-initvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-initvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-initvm-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-initvm-debuginfo-i586");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-initvm-i586");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-mkbaselibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-mkbaselibs-sle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-mkdrpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-download_files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-format_spec_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-source_validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:osc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"build-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"build-initvm-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"build-initvm-debuginfo-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"build-mkbaselibs-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"build-mkbaselibs-sle-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"build-mkdrpms-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"obs-service-download_files-0.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"obs-service-format_spec_file-0.4.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"obs-service-source_validator-0.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"osc-0.134.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"build-initvm-debuginfo-32bit-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"build-initvm-debuginfo-i586-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"build-initvm-i586-2012.03.06-10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"build-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"build-initvm-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"build-initvm-debuginfo-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"build-mkbaselibs-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"build-mkbaselibs-sle-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"build-mkdrpms-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"obs-service-download_files-0.3-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"obs-service-format_spec_file-0.4.1-13.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"obs-service-source_validator-0.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"osc-0.134.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"build-initvm-debuginfo-32bit-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"build-initvm-debuginfo-i586-2012.03.06-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"build-initvm-i586-2012.03.06-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "osc");
}
