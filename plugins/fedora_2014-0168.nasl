#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-0168.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71920);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:06:07 $");

  script_xref(name:"FEDORA", value:"2014-0168");

  script_name(english:"Fedora 19 : x2goserver-4.0.1.10-1.fc19 (2014-0168)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release pulls in all changes that got introduced in the Baikal
LTS release 4.0.0.8, including a severe vulnerability in
x2gocleansessions. Gains of the LTS version 4.0.0.8 of x2goserver 
are :

o Improve parsing of the NX session.log file. Fix session
suspending/resuming when in fails in some occasions. o Fix severe
vulnerability in x2gocleansessions. o Sanitize session ID string, port
numbers, display numbers and agent PID numbers before writing them as
strings to the session DB.

Please note::: This release fixes a severe vulnerability in X2Go
Server that allowed an attacker with user permissions to gain root
access tothe X2Go Server machine. Everyone, please upgrade your X2Go
Server installations.

New gains of the version 4.0.1.10 of x2goserver are :

o Fix x2goresume-session that we broke in 4.0.1.9. o Ship
x2goserver-fmbindings o Allow enabling/disabling of TCP listening of
x2goagent.

  - Disable Xsession support for now - Debian specific (Bug
    #1038834)

Update to 4.0.1.9 - incorporate changes from 4.0.0.7 LTS bugfix
release.

  - Drop incorrect keyboard patch- Use mktemp instead of
    tempfile

    - Fix Xsession.d link creation

    - Add patch to fix keyboard setting (bug #1033876)

Update to 4.0.1.8 :

  - Fix resizing when resuming sessions.

    - Fix automatic keyboard setup (via x2gosetkeyboard)
      while resuming a session. (Fixes: #285).

    - Provide sudoers.d/x2goserver file that allows sudoed
      commands under KDE (by pertaining the env var
      QT_GRAPHICSSYSTEM. (Fixes: #276).

    - With PostgreSQL as session db backend, prevent the
      root user from launching sessions. Also, prevent
      x2gouser_root from being added as a PostgreSQL user.
      (Fixes: #310).

    - Execute DB status changes as late as possible during
      suspend / terminate.

    - Start/resume rootless sessions without geometry
      parameter. Esp. using X2GO_GEOMETRY=fullscreen for
      rootless sessions lead to an extra 1x1 px session
      window (nxagentCreateIconWindow in nxagent's
      Window.c).

    - Typo fix in x2goruncommand (for MATE session startup).

    - Make umask that is used when mounting client-side
      folders via SSHFS configurable in x2goserver.conf.
      (Fixes: #331).

    - Use bash-builtin 'type' instead of to be avoided
      'which'. (Fixes: #305).

    - Disable Xsession support for now - Debian specific
      (Bug #1038834)

Update to 4.0.1.9 - incorporate changes from 4.0.0.7 LTS bugfix
release.

  - Drop incorrect keyboard patch

    - Use mktemp instead of tempfile

    - Fix Xsession.d link creation

    - Add patch to fix keyboard setting (bug #1033876)

Update to 4.0.1.8 :

  - Fix resizing when resuming sessions.

    - Fix automatic keyboard setup (via x2gosetkeyboard)
      while resuming a session. (Fixes: #285).

    - Provide sudoers.d/x2goserver file that allows sudoed
      commands under KDE (by pertaining the env var
      QT_GRAPHICSSYSTEM. (Fixes: #276).

    - With PostgreSQL as session db backend, prevent the
      root user from launching sessions. Also, prevent
      x2gouser_root from being added as a PostgreSQL user.
      (Fixes: #310).

    - Execute DB status changes as late as possible during
      suspend / terminate.

    - Start/resume rootless sessions without geometry
      parameter. Esp. using X2GO_GEOMETRY=fullscreen for
      rootless sessions lead to an extra 1x1 px session
      window (nxagentCreateIconWindow in nxagent's
      Window.c).

    - Typo fix in x2goruncommand (for MATE session startup).

    - Make umask that is used when mounting client-side
      folders via SSHFS configurable in x2goserver.conf.
      (Fixes: #331).

    - Use bash-builtin 'type' instead of to be avoided
      'which'. (Fixes: #305).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1038834"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08fefe61"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected x2goserver package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:x2goserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"x2goserver-4.0.1.10-1.fc19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "x2goserver");
}
