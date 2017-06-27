#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1159.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93995);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/12 13:47:11 $");

  script_cve_id("CVE-2014-0012");

  script_name(english:"openSUSE Security Update : python-Jinja2 (openSUSE-2016-1159)");
  script_summary(english:"Check for the openSUSE-2016-1159 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-Jinja2 fixes the following issues :

Update to version 2.8 :

  - Added `target` parameter to urlize function.

  - Added support for `followsymlinks` to the file system
    loader.

  - The truncate filter now counts the length.

  - Added equalto filter that helps with select filters.

  - Changed cache keys to use absolute file names if
    available instead of load names.

  - Fixed loop length calculation for some iterators.

  - Changed how Jinja2 enforces strings to be native strings
    in Python 2 to work when people break their default
    encoding.

  - Added :func:`make_logging_undefined` which returns an
    undefined object that logs failures into a logger.

  - If unmarshalling of cached data fails the template will
    be reloaded now.

  - Implemented a block ``set`` tag.

  - Default cache size was incrased to 400 from a low 50.

  - Fixed ``is number`` test to accept long integers in all
    Python versions.

  - Changed ``is number`` to accept Decimal as a number.

  - Added a check for default arguments followed by
    non-default arguments. This change makes ``{% macro m(x,
    y=1, z) %}...{% endmacro %}`` a syntax error. The
    previous behavior for this code was broken anyway
    (resulting in the default value being applied to `y`).

  - Add ability to use custom subclasses of
    ``jinja2.compiler.CodeGenerator`` and
    ``jinja2.runtime.Context`` by adding two new attributes
    to the environment (`code_generator_class` and
    `context_class`) (pull request ``#404``).

  - added support for context/environment/evalctx decorator
    functions on the finalize callback of the environment.

  - escape query strings for urlencode properly. Previously
    slashes were not escaped in that place.

  - Add 'base' parameter to 'int' filter.

  - Update to 2.7.3 (boo#858239, CVE-2014-0012)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=858239"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-Jinja2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-Jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-Jinja2-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-Jinja2-vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"python-Jinja2-2.8-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-Jinja2-emacs-2.8-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-Jinja2-vim-2.8-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-Jinja2 / python-Jinja2-emacs / python-Jinja2-vim");
}
