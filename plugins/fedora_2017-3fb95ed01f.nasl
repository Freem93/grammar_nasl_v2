#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-3fb95ed01f.
#

include("compat.inc");

if (description)
{
  script_id(99408);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2017-0361", "CVE-2017-0362", "CVE-2017-0363", "CVE-2017-0364", "CVE-2017-0365", "CVE-2017-0366", "CVE-2017-0367", "CVE-2017-0368", "CVE-2017-0369", "CVE-2017-0370", "CVE-2017-0372");
  script_xref(name:"FEDORA", value:"2017-3fb95ed01f");

  script_name(english:"Fedora 25 : mediawiki (2017-3fb95ed01f)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - (T109140) (T122209) Special:UserLogin and Special:Search
    allow redirect to interwiki links. (CVE-2017-0363,
    CVE-2017-0364)

  - (T144845) XSS in SearchHighlighter::highlightText() when
    $wgAdvancedSearchHighlighting is true. (CVE-2017-0365)

  - (T125177) API parameters may now be marked as
    'sensitive' to keep their values out of the logs.
    (CVE-2017-0361)

  - (T150044) 'Mark all pages visited' on the watchlist now
    requires a CSRF token. (CVE-2017-0362)

  - (T156184) Escape content model/format url parameter in
    message. (CVE-2017-0368)

  - (T151735) SVG filter evasion using default attribute
    values in DTD declaration. (CVE-2017-0366)

  - (T48143) Spam blacklist ineffective on encoded URLs
    inside file inclusion syntax's link parameter.
    (CVE-2017-0370)

  - (T108138) Sysops can undelete pages, although the page
    is protected against it. (CVE-2017-0369)

The following only affects 1.27 and above and is not included in the
1.23 upgrade :

  - (T161453) LocalisationCache will no longer use the
    temporary directory in its fallback chain when trying to
    work out where to write the cache. (CVE-2017-0367)

The following fix is for the SyntaxHighlight extension :

  - (T158689) Parameters injection in SyntaxHighlight
    results in multiple vulnerabilities. (CVE-2017-0372)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-3fb95ed01f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MediaWiki SyntaxHighlight extension option injection vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"mediawiki-1.27.2-1.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}
