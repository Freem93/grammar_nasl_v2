#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-11688.
#

include("compat.inc");

if (description)
{
  script_id(35265);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252", "CVE-2008-5687", "CVE-2008-5688");
  script_bugtraq_id(32844);
  script_xref(name:"FEDORA", value:"2008-11688");

  script_name(english:"Fedora 8 : mediawiki-1.13.3-41.99.fc8 (2008-11688)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a security release of MediaWiki 1.13.3. Some of the security
issues affect *all* versions of MediaWiki except the versions released
on Dec. 15th, so all site administrators are encouraged to upgrade.
CVEs assigned to the mentioned MediaWiki update: CVE-2008-5249
Cross-site scripting (XSS) vulnerability in MediaWiki 1.13.0 through
1.13.2 allows remote attackers to inject arbitrary web script or HTML
via unspecified vectors. CVE-2008-5250 Cross-site scripting (XSS)
vulnerability in MediaWiki before 1.6.11, 1.12.x before 1.12.2, and
1.13.x before 1.13.3, when Internet Explorer is used and uploads are
enabled, or an SVG scripting browser is used and SVG uploads are
enabled, allows remote authenticated users to inject arbitrary web
script or HTML by editing a wiki page. CVE-2008-5252 Cross-site
request forgery (CSRF) vulnerability in the Special:Import feature in
MediaWiki 1.3.0 through 1.6.10, 1.12.x before 1.12.2, and 1.13.x
before 1.13.3 allows remote attackers to perform unspecified actions
as authenticated users via unknown vectors. As well as other two issue
mentioned in the upstream announcement, treated as security
enhancement rather than vulnerability fixes by upstream: CVE-2008-5687
MediaWiki 1.11 through 1.13.3 does not properly protect against the
download of backups of deleted images, which might allow remote
attackers to obtain sensitive information via requests for files in
images/deleted/. CVE-2008-5688 MediaWiki 1.8.1 through 1.13.3, when
the wgShowExceptionDetails variable is enabled, sometimes provides the
full installation path in a debugging message, which might allow
remote attackers to obtain sensitive information via unspecified
requests that trigger an uncaught exception.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476621"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d40e547d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018166.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8b7881e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 200, 264, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/26");
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
if (rpm_check(release:"FC8", reference:"mediawiki-1.13.3-41.99.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}
