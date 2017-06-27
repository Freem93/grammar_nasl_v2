#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-660.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79241);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/18 14:21:32 $");

  script_cve_id("CVE-2014-5277", "CVE-2014-7189");

  script_name(english:"openSUSE Security Update : docker / go (openSUSE-SU-2014:1411-1)");
  script_summary(english:"Check for the openSUSE-2014-660 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Docker was updated to version 1.3.1 to fix two security issues and
several other bugs.

These security issues were fixed :

  - Prevent fallback to SSL protocols lower than TLS 1.0 for
    client, daemon and registry (CVE-2014-5277).

  - Secure HTTPS connection to registries with certificate
    verification and without HTTP fallback unless
    `--insecure-registry` is specified.

These non-security issues were fixed :

  - Fix issue where volumes would not be shared

  - Fix issue with `--iptables=false` not automatically
    setting `--ip-masq=false`

  - Fix docker run output to non-TTY stdout

  - Fix escaping `$` for environment variables

  - Fix issue with lowercase `onbuild` Dockerfile
    instruction

  - Restrict envrionment variable expansion to `ENV`, `ADD`,
    `COPY`, `WORKDIR`, `EXPOSE`, `VOLUME` and `USER`

  - docker `exec` allows you to run additional processes
    inside existing containers

  - docker `create` gives you the ability to create a
    container via the cli without executing a process

  - `--security-opts` options to allow user to customize
    container labels and apparmor profiles

  - docker `ps` filters

  - Wildcard support to copy/add

  - Move production urls to get.docker.com from
    get.docker.io

  - Allocate ip address on the bridge inside a valid cidr

  - Use drone.io for pr and ci testing

  - Ability to setup an official registry mirror

  - Ability to save multiple images with docker `save`

go was updated to version 1.3.3 to fix one security issue and several
other bugs.

This security issue was fixed :

  - TLS client authentication issue (CVE-2014-7189). These
    non-security issues were fixed :

  - Avoid stripping debuginfo on arm, it fails (and is not
    necessary)

  - Revert the /usr/share/go/contrib symlink as it caused
    problems during update. Moved all go sources to
    /usr/share/go/contrib/src instead of
    /usr/share/go/contrib/src/pkg and created pkg and src
    symlinks in contrib to add it to GOPATH

  - Fixed %go_contribsrcdir value

  - Copy temporary macros.go as go.macros to avoid it to be
    built

  - Do not modify Source: files, because that makes the
    .src.rpm being tied to one specific arch.

  - Removed extra src folder in /usr/share/go/contrib: the
    goal is to transform this folder into a proper entry for
    GOPATH. This folder is now linked to
    %{_libdir}/go/contrib

  - go requires gcc to build sources using cgo

  - tools-packaging.patch: Allow building cover and vet
    tools in $GOROOT_TARGET/pkg/tool instead of
    $GOROOT/pkg/tool. This will allow building go tools as a
    separate package"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=898901"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker / go packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/14");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"docker-bash-completion-1.3.1-5.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-zsh-completion-1.3.1-5.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"go-1.3.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"go-debuginfo-1.3.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"go-debugsource-1.3.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"go-emacs-1.3.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"go-vim-1.3.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"docker-1.3.1-5.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"docker-debuginfo-1.3.1-5.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"docker-debugsource-1.3.1-5.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go / go-debuginfo / go-debugsource / go-emacs / go-vim / docker / etc");
}
