#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-248.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18320);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:38:04 $");

  script_cve_id("CVE-2005-0399");
  script_xref(name:"FEDORA", value:"2005-248");

  script_name(english:"Fedora Core 2 : mozilla-1.7.6-1.2.2 (2005-248)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow bug was found in the way Mozilla processes GIF
images. It is possible for an attacker to create a specially crafted
GIF image, which when viewed by a victim will execute arbitrary code
as the victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0399 to this issue.

A bug was found in the way Mozilla responds to proxy auth requests. It
is possible for a malicious webserver to steal credentials from a
victims browser by issuing a 407 proxy authentication request.
(CVE-2005-0147)

A bug was found in the way Mozilla displays dialog windows. It is
possible that a malicious web page which is being displayed in a
background tab could present the user with a dialog window appearing
to come from the active page. (CVE-2004-1380)

A bug was found in the way Mozilla Mail handles cookies when loading
content over HTTP regardless of the user's preference. It is possible
that a particular user could be tracked through the use of malicious
mail messages which load content over HTTP. (CVE-2005-0149)

A flaw was found in the way Mozilla displays international domain
names. It is possible for an attacker to display a valid URL, tricking
the user into thinking they are viewing a legitimate web page when
they are not. (CVE-2005-0233)

A bug was found in the way Mozilla handles pop-up windows. It is
possible for a malicious website to control the content in an
unrelated site's pop-up window. (CVE-2004-1156)

A bug was found in the way Mozilla saves temporary files. Temporary
files are saved with world readable permissions, which could allow a
local malicious user to view potentially sensitive data.
(CVE-2005-0142)

A bug was found in the way Mozilla handles synthetic middle click
events. It is possible for a malicious web page to steal the contents
of a victims clipboard. (CVE-2005-0146)

A bug was found in the way Mozilla processes XUL content. If a
malicious web page can trick a user into dragging an object, it is
possible to load malicious XUL content. (CVE-2005-0401)

A bug was found in the way Mozilla loads links in a new tab which are
middle clicked. A malicious web page could read local files or modify
privileged chrom settings. (CVE-2005-0141)

A bug was found in the way Mozilla displays the secure site icon. A
malicious web page can use a view-source URL targetted at a secure
page, while loading an insecure page, yet the secure site icon shows
the previous secure state. (CVE-2005-0144)

A bug was found in the way Mozilla displays the secure site icon. A
malicious web page can display the secure site icon by loading a
binary file from a secured site. (CVE-2005-0143)

A bug was found in the way Mozilla displays the download dialog
window. A malicious site can obfuscate the content displayed in the
source field, tricking a user into thinking they are downloading
content from a trusted source. (CVE-2005-0585)

Users of Mozilla are advised to upgrade to this updated package which
contains Mozilla version 1.7.6 to correct these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-March/000802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1443f6d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"mozilla-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-chat-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-debuginfo-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-devel-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-dom-inspector-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-js-debugger-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-mail-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-nspr-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-nspr-devel-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-nss-1.7.6-1.2.2")) flag++;
if (rpm_check(release:"FC2", reference:"mozilla-nss-devel-1.7.6-1.2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla / mozilla-chat / mozilla-debuginfo / mozilla-devel / etc");
}
