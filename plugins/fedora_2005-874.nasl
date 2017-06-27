#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-874.
#

include("compat.inc");

if (description)
{
  script_id(19736);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:06 $");

  script_cve_id("CVE-2005-2871");
  script_xref(name:"FEDORA", value:"2005-874");

  script_name(english:"Fedora Core 3 : mozilla-1.7.10-1.3.2 (2005-874)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mozilla package that fixes a security bug is now available
for Fedora Core 3.

This update has been rated as having critical security impact by the
Fedora Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

A bug was found in the way Mozilla processes certain international
domain names. An attacker could create a specially crafted HTML file,
which when viewed by the victim would cause Mozilla to crash or
possibly execute arbitrary code. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-2871
to this issue.

Users of Mozilla are advised to upgrade to this updated package that
contains a backported patch and is not vulnerable to this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-September/001359.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?639cdc5b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
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
if (rpm_check(release:"FC3", reference:"mozilla-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-chat-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-debuginfo-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-devel-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-dom-inspector-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-js-debugger-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-mail-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-nspr-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-nspr-devel-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-nss-1.7.10-1.3.2")) flag++;
if (rpm_check(release:"FC3", reference:"mozilla-nss-devel-1.7.10-1.3.2")) flag++;


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
