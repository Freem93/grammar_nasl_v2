#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-2313.
#

include("compat.inc");

if (description)
{
  script_id(81584);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 23:06:17 $");

  script_cve_id("CVE-2015-0278");
  script_xref(name:"FEDORA", value:"2015-2313");

  script_name(english:"Fedora 21 : libuv-0.10.34-1.fc21 / nodejs-0.10.36-3.fc21 / v8-3.14.5.10-17.fc21 (2015-2313)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# nodejs

  - tls: re-add 1024-bit SSL certs removed by f9456a2 (Chris
    Dickinson)

  - timers: don't close interval timers when unrefd (Julien
    Gilli)

  - timers: don't mutate unref list while iterating it
    (Julien Gilli)

  - child_process: check execFile args is an array (Sam
    Roberts)

  - child_process: check fork args is an array (Sam Roberts)

  - crypto: update root certificates (Ben Noordhuis)

  - domains: fix issues with abort on uncaught (Julien
    Gilli)

  - timers: Avoid linear scan in _unrefActive. (Julien
    Gilli)

  - timers: fix unref() memory leak (Trevor Norris)

  - debugger: fix when using 'use strict' (Julien Gilli)

# libuv

  - linux: fix epoll_pwait() regression with < 2.6.19 (Ben
    Noordhuis)

  - linux: fix epoll_pwait() sigmask size calculation (Ben
    Noordhuis)

  - linux: fix sigmask size arg in epoll_pwait() call (Ben
    Noordhuis)

  - linux: handle O_NONBLOCK != SOCK_NONBLOCK case (Helge
    Deller)

  - doc: update project links (Ben Noordhuis)

  - unix: add flag for blocking SIGPROF during poll (Ben
    Noordhuis)

  - unix, windows: add uv_loop_configure() function (Ben
    Noordhuis)

# v8

  - Fix debugger and strict mode regression (Julien Gilli)

  - don't busy loop in cpu profiler thread (Ben Noordhuis)

  - add api for aborting on uncaught exception (Julien
    Gilli)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1194651"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b24d9909"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea82449a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150528.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a1797f1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuv, nodejs and / or v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libuv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"libuv-0.10.34-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"nodejs-0.10.36-3.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"v8-3.14.5.10-17.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libuv / nodejs / v8");
}
