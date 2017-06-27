#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-488.
#

include("compat.inc");

if (description)
{
  script_id(24088);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:46:27 $");

  script_xref(name:"FEDORA", value:"2006-488");

  script_name(english:"Fedora Core 4 : mozilla-1.7.13-1.1.fc4 (2006-488)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix several security bugs are now
available.

This update has been rated as having critical security impact by the
Fedora Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several bugs were found in the way Mozilla processes malformed
JavaScript. A malicious web page could modify the content of a
different open web page, possibly stealing sensitive information or
conducting a cross-site scripting attack. (CVE-2006-1731,
CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Mozilla processes certain
JavaScript actions. A malicious web page could execute arbitrary
JavaScript instructions with the permissions of 'chrome', allowing the
page to steal sensitive information or install browser malware.
(CVE-2006-1727, CVE-2006-1728, CVE-2006-1733, CVE-2006-1734,
CVE-2006-1735, CVE-2006-1742)

Several bugs were found in the way Mozilla processes malformed web
pages. A carefully crafted malicious web page could cause the
execution of arbitrary code as the user running Mozilla.
(CVE-2006-0748, CVE-2006-0749, CVE-2006-1730, CVE-2006-1737,
CVE-2006-1738, CVE-2006-1739, CVE-2006-1790)

A bug was found in the way Mozilla displays the secure site icon. If a
browser is configured to display the non-default secure site modal
warning dialog, it may be possible to trick a user into believing they
are viewing a secure site. (CVE-2006-1740)

A bug was found in the way Mozilla allows JavaScript mutation events
on 'input' form elements. A malicious web page could be created in
such a way that when a user submits a form, an arbitrary file could be
uploaded to the attacker. (CVE-2006-1729)

A bug was found in the way Mozilla executes in-line mail forwarding.
If a user can be tricked into forwarding a maliciously crafted mail
message as in-line content, it is possible for the message to execute
JavaScript with the permissions of 'chrome'. (CVE-2006-0884)

Users of Mozilla are advised to upgrade to these updated packages
containing Mozilla version 1.7.13 which corrects these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-May/000019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be26e82c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC4", reference:"mozilla-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-chat-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-debuginfo-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-devel-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-dom-inspector-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-js-debugger-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-mail-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-nspr-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-nspr-devel-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-nss-1.7.13-1.1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"mozilla-nss-devel-1.7.13-1.1.fc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla / mozilla-chat / mozilla-debuginfo / mozilla-devel / etc");
}
