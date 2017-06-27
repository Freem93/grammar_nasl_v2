#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3864.
#

include("compat.inc");

if (description)
{
  script_id(33232);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2007-4782", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-0599", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108");
  script_bugtraq_id(26403, 29009);
  script_xref(name:"FEDORA", value:"2008-3864");

  script_name(english:"Fedora 8 : php-5.2.6-2.fc8 (2008-3864)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release updates PHP to the latest upstream version 5.2.6, fixing
multiple bugs and security issues. See upstream release notes for
further details: http://www.php.net/releases/5_2_5.php
http://www.php.net/releases/5_2_6.php It was discovered that the PHP
escapeshellcmd() function did not properly escape multi-byte
characters which are not valid in the locale used by the script. This
could allow an attacker to bypass quoting restrictions imposed by
escapeshellcmd() and execute arbitrary commands if the PHP script was
using certain locales. Scripts using the default UTF-8 locale are not
affected by this issue. (CVE-2008-2051) PHP functions htmlentities()
and htmlspecialchars() did not properly recognize partial multi-byte
sequences. Certain sequences of bytes could be passed through these
functions without being correctly HTML-escaped. An attacker could use
this flaw to conduct cross-site scripting attack against users of such
browsers. (CVE-2007-5898) It was discovered that a PHP script using
the transparent session ID configuration option, or using the
output_add_rewrite_var() function, could leak session identifiers to
external websites. If a page included an HTML form which is posted to
a third-party website, the user's session ID would be included in the
form data and passed to that website. (CVE-2007-5899) It was
discovered that PHP fnmatch() function did not restrict the length of
the string argument. An attacker could use this flaw to crash the PHP
interpreter where a script used fnmatch() on untrusted input data.
(CVE-2007-4782) It was discovered that PHP did not properly seed its
pseudo-random number generator used by functions such as rand() and
mt_rand(), possibly allowing an attacker to easily predict the
generated pseudo-random values. (CVE-2008-2107, CVE-2008-2108)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_5.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_6.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=285881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=382411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=382431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=445003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=445006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=445684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=445685"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-June/011516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2056591"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"php-5.2.6-2.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
