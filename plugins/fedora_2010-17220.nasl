#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-17220.
#

include("compat.inc");

if (description)
{
  script_id(50568);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/11 13:24:18 $");

  script_cve_id("CVE-2010-3867", "CVE-2010-4221");
  script_bugtraq_id(44562);
  script_xref(name:"FEDORA", value:"2010-17220");

  script_name(english:"Fedora 12 : proftpd-1.3.3c-1.fc12 (2010-17220)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update to the current upstream maintenance release, which
addresses two security issues that can be exploited by malicious users
to manipulate certain data and compromise a vulnerable system.

  - A logic error in the code for processing user input
    containing the Telnet IAC (Interpret As Command) escape
    sequence can be exploited to cause a stack-based buffer
    overflow by sending specially crafted input to the FTP
    or FTPS service. Successful exploitation may allow
    execution of arbitrary code. This has been assigned the
    name CVE-2010-4221. More details can be found at
    http://bugs.proftpd.org/show_bug.cgi?id=3521

  - An input validation error within the 'mod_site_misc'
    module can be exploited to e.g. create and delete
    directories, create symlinks, and change the time of
    files located outside a writable directory. Only
    configurations using 'mod_site_misc', which is not
    enabled by default, and where the attacker has write
    access to a directory, are vulnerable to this issue,
    which has been assigned CVE-2010-3867. More details can
    be found at http://bugs.proftpd.org/show_bug.cgi?id=3519

The update from 1.3.2d to 1.3.3c also includes a large number of
non-security bugfixes and a number of additional loadable modules for
enhanced functionality :

  - mod_geoip

    - mod_sftp

    - mod_sftp_pam

    - mod_sftp_sql

    - mod_shaper

    - mod_sql_passwd

    - mod_tls_shmcache

There is also a new utility 'ftpscrub' for scrubbing the scoreboard
file.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.proftpd.org/show_bug.cgi?id=3519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.proftpd.org/show_bug.cgi?id=3521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=651602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=651607"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/050726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d1f02cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"proftpd-1.3.3c-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd");
}
