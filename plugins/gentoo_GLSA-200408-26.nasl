#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-26.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14582);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/04/28 18:42:38 $");

  script_cve_id("CVE-2004-0797");
  script_osvdb_id(9360, 9361);
  script_xref(name:"GLSA", value:"200408-26");

  script_name(english:"GLSA-200408-26 : zlib: Denial of service vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200408-26
(zlib: Denial of service vulnerability)

    zlib contains a bug in the handling of errors in the 'inflate()' and
    'inflateBack()' functions.
  
Impact :

    An attacker could exploit this vulnerability to launch a Denial of
    Service attack on any application using the zlib library.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of zlib."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openpkg.org/security/OpenPKG-SA-2004.038-zlib.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All zlib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=sys-libs/zlib-1.2.1-r3'
    # emerge '>=sys-libs/zlib-1.2.1-r3'
    You should also run revdep-rebuild to rebuild any packages that depend
    on older versions of zlib :
    # revdep-rebuild"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"sys-libs/zlib", unaffected:make_list("ge 1.2.1-r3"), vulnerable:make_list("le 1.2.1-r2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zlib");
}
