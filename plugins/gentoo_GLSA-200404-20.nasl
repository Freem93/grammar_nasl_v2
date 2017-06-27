#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14485);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2004-0372", "CVE-2004-1951");
  script_osvdb_id(5594, 5739);
  script_xref(name:"GLSA", value:"200404-20");

  script_name(english:"GLSA-200404-20 : Multiple vulnerabilities in xine");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200404-20
(Multiple vulnerabilities in xine)

    Several vulnerabilities were found in xine-ui and xine-lib. By opening
    a malicious MRL in any xine-lib based media player, an attacker can
    write arbitrary content to an arbitrary file, only restricted by the
    permissions of the user running the application. By opening a malicious
    playlist in the xine-ui media player, an attacker can write arbitrary
    content to an arbitrary file, only restricted by the permissions of the
    user running xine-ui. Finally, a temporary file is created in an
    insecure manner by the xine-check and xine-bugreport scripts,
    potentially allowing a local attacker to use a symlink attack.
  
Impact :

    These three vulnerabilities may allow an attacker to corrupt system
    files, thus potentially leading to a Denial of Service. It is also
    theoretically possible, though very unlikely, to use these
    vulnerabilities to elevate the privileges of the attacker.
  
Workaround :

    There is no known workaround at this time. All users are advised to
    upgrade to the latest available versions of xine-ui and xine-lib."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xinehq.de/index.php/security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://nettwerked.mg2.org/advisories/xinebug"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users of xine-ui or another xine-based player should upgrade to the
    latest stable versions:
    # emerge sync
    # emerge -pv '>=media-video/xine-ui-0.9.23-r2'
    # emerge '>=media-video/xine-ui-0.9.23-r2'
    # emerge -pv '>=media-libs/xine-lib-1_rc3-r3'
    # emerge '>=media-libs/xine-lib-1_rc3-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-ui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"media-video/xine-ui", unaffected:make_list("ge 0.9.23-r2"), vulnerable:make_list("le 0.9.23-r1"))) flag++;
if (qpkg_check(package:"media-libs/xine-lib", unaffected:make_list("ge 1_rc3-r3"), vulnerable:make_list("le 1_rc3-r2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "media-video/xine-ui / media-libs/xine-lib");
}
