#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-22677.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71381);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/19 21:47:13 $");

  script_cve_id("CVE-2013-7070", "CVE-2013-7071");
  script_bugtraq_id(63913, 64178, 64264);
  script_xref(name:"FEDORA", value:"2013-22677");

  script_name(english:"Fedora 19 : monitorix-3.4.0-1.fc19 (2013-22677)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"3.4.0 - 02-Dec-2013 ====================

  - Added a complete statistical Memcached graph. [#27]

    - Added support for different BIND stats versions (2 and
      3 right now). (thanks to Ivo Brhel, ivb AT volny.cz)

  - Added two new alerts in the 'disk' graph in order to
    know if a disk drive has exceeded or reached a threshold
    for reallocated and pending sectors. (suggested by
    Matthew Connelly, maff AT maff.im)

  - Added a new option called 'max_historic_years' (with a
    default value of 1), which enables the ability to have
    up to 5 years of data. Beware with this option because
    it generates a new '.rrd' file every time the value is
    extended, losing the current historical data. (suggested
    by Mohan Reddy, Mohan.Reddy AT analog.com)

  - Improved the regexp when collecting data from devices's
    interrupts which also fixes some annoying messages on
    using non-numeric arguments.

  - Added support for the Pure-FTPd logs in the 'serv' and
    'ftp' graphs.

    - Added the new configuration option 'https_url'. [#31]

    - Fixed error messages about use of uninitialized values
      in 'system' graph on BSD systems.

  - Fixed error messages about not numeric argument in
    addition in 'fs' graph on BSD systems.

  - Fixed in 'emailreports' to use the command line
    'hostname' if the variable $ENV{HOSTNAME} is not defined
    (Debian/Ubuntu and perhaps other systems). (thanks to
    Skibbi, skibbi AT gmail.com for pointing this out)

  - Fixed the error message 'String ends after the = sign on
    CDEF:allvalues=' in the 'int' graph (the Interrupts
    graph is pending to have a complete rewrite).

  - Fixed the 'int' graph in order to be more compatible
    with Raspberry Pi.

    - Fixed in 'bind.pm' to store a 0 value if threads are
      disabled. [#29]

    - Fixed to correctly sent images in graphs 'proc',
      'port' and 'fail2ban' when using emailreports. (thanks
      to Benoit Segond von Banchet, bjm.segondvonbanchet AT
      telfort.nl for pointing this out)

  - Fixed to show the real hostname in the emailreports.

    - Fixed the 'int' graph in order to be compatible with
      Excito B3 product. (thanks to Patrick Fallberg,
      patrick AT fallberg.net for pointing this out)

  - Fixed to correctly sanitize the input string in the
    built-in HTTP server which led into a number of security
    vulnerabilities. [#30]

  - Fixed the lack of minimum definition in some data
    sources of 'bind' graph. (thanks to Andreas Itzchak
    Rehberg, izzy AT qumran.org for pointing this out)

  - Fixed a fail to adequately sanitize request strings of
    malicious JavaScript. [#30] (thanks to Jacob Amey, jamey
    AT securityinspection.com for pointing this out)

  - Fixed a typo in monitorix.service. [#32]

    - Fixed the requests value in the 'nginx' graph. Now it
      honours the label to show the value per second,
      instead of per minute. (thanks to Martin Culak, culak
      AT firma.azet.sk for pointing this out)

  - Small fixes and typos.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1038071"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123445.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3114cce"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected monitorix package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:monitorix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC19", reference:"monitorix-3.4.0-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "monitorix");
}
