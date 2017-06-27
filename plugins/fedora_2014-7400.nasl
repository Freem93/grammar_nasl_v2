#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-7400.
#

include("compat.inc");

if (description)
{
  script_id(76102);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:40:32 $");

  script_cve_id("CVE-2014-3982", "CVE-2014-3986");
  script_bugtraq_id(67844, 67931);
  script_xref(name:"FEDORA", value:"2014-7400");

  script_name(english:"Fedora 20 : lynis-1.5.6-1.fc20 (2014-7400)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"== 1.5.6 (2014-06-12) ==

New :

  - Test for PHP binary and PHP version

    - Don't perform register_global test for systems running
      PHP 5.4.0 and later [PHP-2368]

    - Debug function (can be activated via --debug or
      profile)

Changes :

  - Extended IsRunning function

    - Removed suggestion from secure shell test [SHLL-6202]

    - Check for idle session handlers [SHLL-6220]

    - Also check for apache2 binary (file instead of
      directory)

    - New report values: session_timeout_enabled and
      session_timeout_method

    - New report value for plugins: plugins_enabled

    - Fixed test to determine active TCP sessions on Linux
      [NETW-3012]

== 1.5.5 (2014-06-08) ==

New :

  - Check for nginx access logging [HTTP-6712]

    - Check for missing error logs in nginx [HTTP-6714]

    - Check for debug mode in nginx [HTTP-6716]

Changes :

  - Extended SSL test for nginx when using listen statements

    - Allow debugging via profile (config:debug:yes)

    - Check if discovered httpd file is actually a file

    - Improved temporary file creation related to security
      notice

    - Adjustments to screen output

Security Note: This releases solves two issues regarding the usage of
temporary files (predictability of the file names). You are advised to
upgrade to this version as soon as possible. For more information see
the our blog post:
http://linux-audit.com/lynis-security-notice-154-and-older/

== 1.5.4 (2014-06-04) ==

New :

  - Check additional configuration files for nginx
    [HTTP-6706]

    - Analysis of nginx settings [HTTP-6708]

    - New test for SSL configuration of nginx [HTTP-6710]

Changes :

  - Altered SMBD version check for Mac OS

    - Small adjustments to report for readability

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://linux-audit.com/lynis-security-notice-154-and-older/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1104999"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-June/134443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?768399e6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynis package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lynis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"lynis-1.5.6-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynis");
}
