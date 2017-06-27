#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-246.
#

include("compat.inc");

if (description)
{
  script_id(19632);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:04 $");

  script_cve_id("CVE-2005-0399");
  script_xref(name:"FEDORA", value:"2005-246");

  script_name(english:"Fedora Core 3 : firefox-1.0.2-1.3.1 (2005-246)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow bug was found in the way Firefox processes GIF
images. It is possible for an attacker to create a specially crafted
GIF image, which when viewed by a victim will execute arbitrary code
as the victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0399 to this issue.

A bug was found in the way Firefox processes XUL content. If a
malicious web page can trick a user into dragging an object, it is
possible to load malicious XUL content. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0401
to this issue.

A bug was found in the way Firefox bookmarks content to the sidebar.
If a user can be tricked into bookmarking a malicious web page into
the sidebar panel, that page could execute arbitrary programs. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0402 to this issue.

Users of Firefox are advised to upgrade to this updated package which
contains Firefox version 1.0.2 and is not vulnerable to these issues.

Additionally, there was a bug found in the way Firefox rendered some
fonts, notably the Tahoma font while italicized. This issue has been
filed as Bug 150041 (bugzilla.redhat.com). This updated package
contains a fix for this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-March/000792.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78830c62"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"firefox-1.0.2-1.3.1")) flag++;
if (rpm_check(release:"FC3", reference:"firefox-debuginfo-1.0.2-1.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
