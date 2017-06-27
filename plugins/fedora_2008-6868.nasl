#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6868.
#

include("compat.inc");

if (description)
{
  script_id(33769);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2008-3456", "CVE-2008-3457");
  script_bugtraq_id(30420);
  script_xref(name:"FEDORA", value:"2008-6868");

  script_name(english:"Fedora 9 : phpMyAdmin-2.11.8.1-1.fc9 (2008-6868)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update solves PMASA-2008-6 (phpMyAdmin security announcement)
from 2008-07-28: Cross-site Framing; XSS in setup.php; see
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-6 -
[interface] Table list pagination in navi - [profiling] Profiling
causes query to be executed again (really causes a problem in case of
INSERT/UPDATE) - [import] SQL file import very slow on Windows -
[XHTML] problem with tabindex and radio fields - [interface] tabindex
not set correctly - [views] VIEW name created via the GUI was not
protected with backquotes - [interface] Deleting multiple views (space
in name) - [parser] SQL parser removes essential space - [export] CSV
for MS Excel incorrect escaping of double quotes - [interface] Font
size option problem when no config file - [relation] Relationship view
should check for changes - [history] Do not save too big queries in
history - [security] Do not show version info on login screen -
[import] Potential data loss on import resubmit - [export] Safari and
timedate - [import, export] Import/Export fails because of Mac files -
[security] protection against cross- frame scripting and new directive
AllowThirdPartyFraming - [security] possible XSS during setup -
[interface] revert language changing problem introduced with 2.11.7.1
phpMyAdmin 2.11.8.1 is a bugfix-only version containing normal bug
fixes and two security fixes. This version is identical to 2.11.8,
except it includes a fix for a notice about 'lang'.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=456637"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/013196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dff8dd45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/31");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"phpMyAdmin-2.11.8.1-1.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
