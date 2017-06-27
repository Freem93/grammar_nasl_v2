#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-2367.
#

include("compat.inc");

if (description)
{
  script_id(52759);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/20 22:05:53 $");

  script_bugtraq_id(46605);
  script_xref(name:"FEDORA", value:"2011-2367");

  script_name(english:"Fedora 15 : php-pear-1.9.2-1.fc15 (2011-2367)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream Changelog :

Important! This is a security fix release. The advisory can be found
at http://pear.php.net/advisory-20110228.txt

Bugs :

  - Fixed Bug #17463: Regression: On Windows, svntag [patch
    by doconnor]

    - Fixed Bug #17641: pecl-list doesn't sort packages by
      name [dufuz]

    - Fixed Bug #17781: invalid argument warning on foreach
      due to an empty optional dependencie [dufuz]

    - Fixed Bug #17801: PEAR run-tests wrongly detects
      php-cgi [patch by David Jean Louis (izi)]

    - Fixed Bug #17839: pear svntag does not tag package.xml
      file [dufuz]

    - Fixed Bug #17986: PEAR Installer cannot handle files
      moved between packages [dufuz]

    - Fixed Bug #17997: Strange output if directories are
      not writeable [dufuz]

    - Fixed Bug #18001: PEAR/RunTest coverage fails [dufuz]

    - Fixed Bug #18056 [SECURITY]: Symlink attack in PEAR
      install [dufuz]

    - Fixed Bug #18218: 'pear package' does not allow the
      use of late static binding [dufuz and Christer
      Edvartsen]

    - Fixed Bug #18238: Wrong return code from 'pear help'
      [till]

    - Fixed Bug #18308: Broken error message about missing
      channel validator [yunosh]

This feature is implemented as a result of #18056

  - Implemented Request #16648: Use TMPDIR for builds
    instead of /var/tmp [dufuz]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pear.php.net/advisory-20110228.txt"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/056488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bc07b01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"php-pear-1.9.2-1.fc15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear");
}
