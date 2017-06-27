#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-3848.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38957);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2008-2829", "CVE-2008-3658", "CVE-2008-3660", "CVE-2008-5498", "CVE-2008-5557", "CVE-2008-5658", "CVE-2009-0754", "CVE-2009-1271");
  script_bugtraq_id(29829, 30649, 31612, 32625, 32948, 33002, 33542);
  script_xref(name:"FEDORA", value:"2009-3848");

  script_name(english:"Fedora 9 : maniadrive-1.2-13.fc9 / php-5.2.9-2.fc9 (2009-3848)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to PHP 5.2.9 A heap-based buffer overflow flaw was found in
PHP's mbstring extension. A remote attacker able to pass arbitrary
input to a PHP script using mbstring conversion functions could cause
the PHP interpreter to crash or, possibly, execute arbitrary code.
(CVE-2008-5557) A directory traversal flaw was found in PHP's
ZipArchive::extractTo function. If PHP is used to extract a malicious
ZIP archive, it could allow an attacker to write arbitrary files
anywhere the PHP process has write permissions. (CVE-2008-5658) A
buffer overflow flaw was found in PHP's imageloadfont function. If a
PHP script allowed a remote attacker to load a carefully crafted font
file, it could cause the PHP interpreter to crash or, possibly,
execute arbitrary code. (CVE-2008-3658) A memory disclosure flaw was
found in the PHP gd extension's imagerotate function. A remote
attacker able to pass arbitrary values as the 'background color'
argument of the function could, possibly, view portions of the PHP
interpreter's memory. (CVE-2008-5498) A cross-site scripting flaw was
found in a way PHP reported errors for invalid cookies. If the PHP
interpreter had 'display_errors' enabled, a remote attacker able to
set a specially crafted cookie on a victim's system could possibly
inject arbitrary HTML into an error message generated by PHP.
(CVE-2008-5814) A flaw was found in the handling of the
'mbstring.func_overload' configuration setting. A value set for one
virtual host, or in a user's .htaccess file, was incorrectly applied
to other virtual hosts on the same server, causing the handling of
multibyte character strings to not work correctly. (CVE-2009-0754) A
flaw was found in PHP's json_decode function. A remote attacker could
use this flaw to create a specially crafted string which could cause
the PHP interpreter to crash while being decoded in a PHP script.
(CVE-2009-1271) A flaw was found in the use of the uw-imap library by
the PHP 'imap' extension. This could cause the PHP interpreter to
crash if the 'imap' extension was used to read specially crafted mail
messages with long headers. (CVE-2008-2829)
http://www.php.net/releases/5_2_7.php
http://www.php.net/releases/5_2_8.php
http://www.php.net/releases/5_2_9.php
http://www.php.net/ChangeLog-5.php#5.2.9

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.2.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_7.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_8.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_9.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=459529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=459572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=474824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=478425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=478848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=479272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=494530"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-May/024366.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9da9790c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-May/024369.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dfb87a7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected maniadrive and / or php packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 119, 134, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"maniadrive-1.2-13.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"php-5.2.9-2.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php");
}
