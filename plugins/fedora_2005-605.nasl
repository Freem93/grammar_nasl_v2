#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-605.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19262);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:38:05 $");

  script_cve_id("CVE-2005-2260");
  script_xref(name:"FEDORA", value:"2005-605");

  script_name(english:"Fedora Core 4 : firefox-1.0.6-1.1.fc4 (2005-605)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source Web browser.

A bug was found in the way Firefox handled synthetic events. It is
possible that Web content could generate events such as keystrokes or
mouse clicks that could be used to steal data or execute malicious
JavaScript code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-2260 to this issue.

A bug was found in the way Firefox executed JavaScript in XBL
controls. It is possible for a malicious web page to leverage this
vulnerability to execute other JavaScript based attacks even when
JavaScript is disabled. (CVE-2005-2261)

A bug was found in the way Firefox set an image as the desktop
wallpaper. If a user chooses the 'Set As Wallpaper...' context menu
item on a specially crafted image, it is possible for an attacker to
execute arbitrary code on a victim's machine. (CVE-2005-2262)

A bug was found in the way Firefox installed its extensions. If a user
can be tricked into visiting a malicious web page, it may be possible
to obtain sensitive information such as cookies or passwords.
(CVE-2005-2263)

A bug was found in the way Firefox handled the _search target. It is
possible for a malicious website to inject JavaScript into an already
open web page. (CVE-2005-2264)

A bug was found in the way Firefox handled certain JavaScript
functions. It is possible for a malicious web page to crash the
browser by executing malformed JavaScript code. (CVE-2005-2265)

A bug was found in the way Firefox handled multiple frame domains. It
is possible for a frame as part of a malicious website to inject
content into a frame that belongs to another domain. This issue was
previously fixed as CVE-2004-0718 but was accidentally disabled.
(CVE-2005-1937)

A bug was found in the way Firefox handled child frames. It is
possible for a malicious framed page to steal sensitive information
from its parent page. (CVE-2005-2266)

A bug was found in the way Firefox opened URLs from media players. If
a media player opens a URL that is JavaScript, JavaScript is executed
with access to the currently open web page. (CVE-2005-2267)

A design flaw was found in the way Firefox displayed alerts and
prompts. Alerts and prompts were given the generic title [JavaScript
Application] which prevented a user from knowing which site created
them. (CVE-2005-2268)

A bug was found in the way Firefox handled DOM node names. It is
possible for a malicious site to overwrite a DOM node name, allowing
certain privileged chrome actions to execute the malicious JavaScript.
(CVE-2005-2269)

A bug was found in the way Firefox cloned base objects. It is possible
for Web content to navigate up the prototype chain to gain access to
privileged chrome objects. (CVE-2005-2270)

Users of Firefox are advised to upgrade to this updated package that
contains Firefox version 1.0.6 and is not vulnerable to these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-July/001101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e6fb068"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/21");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"firefox-1.0.6-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"firefox-debuginfo-1.0.6-1.1.fc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
