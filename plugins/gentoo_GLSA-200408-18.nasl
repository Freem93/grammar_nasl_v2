#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-18.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14574);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-1475");
  script_osvdb_id(8409);
  script_xref(name:"GLSA", value:"200408-18");

  script_name(english:"GLSA-200408-18 : xine-lib: VCD MRL buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200408-18
(xine-lib: VCD MRL buffer overflow)

    xine-lib contains a bug where it is possible to overflow the vcd://
    input source identifier management buffer through carefully crafted
    playlists.
  
Impact :

    An attacker may construct a carefully-crafted playlist file which will
    cause xine-lib to execute arbitrary code with the permissions of the
    user. In order to conform with the generic naming standards of most
    Unix-like systems, playlists can have extensions other than .asx (the
    standard xine playlist format), and made to look like another file
    (MP3, AVI, or MPEG for example). If an attacker crafts a playlist with
    a valid header, they can insert a VCD playlist line that can cause a
    buffer overflow and possible shellcode execution.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of xine-lib."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.open-security.org/advisories/6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All xine-lib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=media-libs/xine-lib-1_rc5-r3'
    # emerge '>=media-libs/xine-lib-1_rc5-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/xine-lib", unaffected:make_list("ge 1_rc5-r3"), vulnerable:make_list("le 1_rc5-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xine-lib");
}
