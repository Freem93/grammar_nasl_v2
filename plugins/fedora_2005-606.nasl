#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-606.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19264);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/21 21:38:05 $");

  script_xref(name:"FEDORA", value:"2005-606");

  script_name(english:"Fedora Core 4 : thunderbird-1.0.6-1.1.fc4 (2005-606)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird is a standalone mail and newsgroup client.

A bug was found in the way Thunderbird handled anonymous functions
during regular expression string replacement. It is possible for a
malicious HTML mail to capture a random block of client memory. The
Common Vulnerabilities and Exposures project has assigned this bug the
name CVE-2005-0989.

A bug was found in the way Thunderbird validated several XPInstall
related JavaScript objects. A malicious HTML mail could pass other
objects to the XPInstall objects, resulting in the JavaScript
interpreter jumping to arbitrary locations in memory. (CVE-2005-1159)

A bug was found in the way the Thunderbird privileged UI code handled
DOM nodes from the content window. An HTML message could install
malicious JavaScript code or steal data when a user performs
commonplace actions such as clicking a link or opening the context
menu. (CVE-2005-1160)

A bug was found in the way Thunderbird executed JavaScript code.
JavaScript executed from HTML mail should run with a restricted access
level, preventing dangerous actions. It is possible that a malicious
HTML mail could execute JavaScript code with elevated privileges,
allowing access to protected data and functions. (CVE-2005-1532)

A bug was found in the way Thunderbird executed JavaScript in XBL
controls. It is possible for a malicious HTML mail to leverage this
vulnerability to execute other JavaScript based attacks even when
JavaScript is disabled. (CVE-2005-2261)

A bug was found in the way Thunderbird handled certain JavaScript
functions. It is possible for a malicious HTML mail to crash the
client by executing malformed JavaScript code. (CVE-2005-2265)

A bug was found in the way Thunderbird handled child frames. It is
possible for a malicious framed HTML mail to steal sensitive
information from its parent frame. (CVE-2005-2266)

A bug was found in the way Thunderbird handled DOM node names. It is
possible for a malicious HTML mail to overwrite a DOM node name,
allowing certain privileged chrome actions to execute the malicious
JavaScript. (CVE-2005-2269)

A bug was found in the way Thunderbird cloned base objects. It is
possible for HTML content to navigate up the prototype chain to gain
access to privileged chrome objects. (CVE-2005-2270)

Users of Thunderbird are advised to upgrade to this updated package
that contains Thunderbird version 1.0.6 and is not vulnerable to these
issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-July/001102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb1c5c1f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-debuginfo");
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
if (rpm_check(release:"FC4", reference:"thunderbird-1.0.6-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"thunderbird-debuginfo-1.0.6-1.1.fc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
