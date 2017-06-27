#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-1176.
#

include("compat.inc");

if (description)
{
  script_id(81170);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:57:25 $");

  script_xref(name:"FEDORA", value:"2015-1176");

  script_name(english:"Fedora 20 : privoxy-3.0.23-1.fc20 (2015-1176)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was reported [1] that Privoxy 3.0.23 contains fixes for the
following security issues :

  - Fixed a DoS issue in case of client requests with
    incorrect chunk-encoded body. When compiled with
    assertions enabled (the default) they could previously
    cause Privoxy to abort(). Reported by Matthew Daley.
    http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/
    jcc.c?r1=1.433&r2=1.434

  - Fixed multiple segmentation faults and memory leaks in
    the pcrs code. This fix also increases the chances that
    an invalid pcrs command is rejected as such. Previously
    some invalid commands would be loaded without error.
    Note that Privoxy's pcrs sources (action and filter
    files) are considered trustworthy input and should not
    be writable by untrusted third-parties.
    http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/
    pcrs.c?r1=1.46&r2=1.47

  - Fixed an 'invalid read' bug which could at least
    theoretically cause Privoxy to crash.
    http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/
    parsers.c?r1=1.297&r2=1.298

[1]: http://seclists.org/oss-sec/2015/q1/259

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/jcc.c?r1=1.433&r2=1.434
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02038803"
  );
  # http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/parsers.c?r1=1.297&r2=1.298
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc0894c2"
  );
  # http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/pcrs.c?r1=1.46&r2=1.47
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e70b2d80"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2015/q1/259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185926"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/149091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10bbbf22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected privoxy package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:privoxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"privoxy-3.0.23-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "privoxy");
}
