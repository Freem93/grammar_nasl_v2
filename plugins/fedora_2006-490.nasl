#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-490.
#

include("compat.inc");

if (description)
{
  script_id(24090);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:46:27 $");

  script_xref(name:"FEDORA", value:"2006-490");

  script_name(english:"Fedora Core 5 : thunderbird-1.5.0.2-1.1.fc5 (2006-490)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix various bugs are now available
for Fedora Core 4.

This update has been rated as having critical security impact by the
Fedora Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several bugs were found in the way Thunderbird processes malformed
JavaScript. A malicious HTML mail message could modify the content of
a different open HTML mail message, possibly stealing sensitive
information or conducting a cross-site scripting attack. Please note
that JavaScript support is disabled by default in Thunderbird.
(CVE-2006-1731, CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Thunderbird processes certain
JavaScript actions. A malicious HTML mail message could execute
arbitrary JavaScript instructions with the permissions of 'chrome',
allowing the page to steal sensitive information or install browser
malware. Please note that JavaScript support is disabled by default in
Thunderbird. (CVE-2006-0292, CVE-2006-0296, CVE-2006-1727,
CVE-2006-1728, CVE-2006-1733, CVE-2006-1734, CVE-2006-1735,
CVE-2006-1742)

Several bugs were found in the way Thunderbird processes malformed
HTML mail messages. A carefully crafted malicious HTML mail message
could cause the execution of arbitrary code as the user running
Thunderbird. (CVE-2006-0748, CVE-2006-0749, CVE-2006-1724,
CVE-2006-1730, CVE-2006-1737, CVE-2006-1738, CVE-2006-1739,
CVE-2006-1790)

A bug was found in the way Thunderbird processes certain inline
content in HTML mail messages. It may be possible for a remote
attacker to send a carefully crafted mail message to the victim, which
will fetch remote content, even if Thunderbird is configured not to
fetch remote content. (CVE-2006-1045)

A bug was found in the way Thunderbird executes in-line mail
forwarding. If a user can be tricked into forwarding a maliciously
crafted mail message as in-line content, it is possible for the
message to execute JavaScript with the permissions of 'chrome'.
(CVE-2006-0884)

Users of Thunderbird are advised to upgrade to these updated packages
containing Thunderbird version 1.5.0.2, which is not vulnerable to
these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-May/000021.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ef33df2"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"thunderbird-1.5.0.2-1.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"thunderbird-debuginfo-1.5.0.2-1.1.fc5")) flag++;


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
