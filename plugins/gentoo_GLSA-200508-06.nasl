#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200508-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19439);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-2102", "CVE-2005-2103");
  script_bugtraq_id(14531);
  script_osvdb_id(18668, 18669);
  script_xref(name:"GLSA", value:"200508-06");

  script_name(english:"GLSA-200508-06 : Gaim: Remote execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200508-06
(Gaim: Remote execution of arbitrary code)

    Brandon Perry discovered that Gaim is vulnerable to a heap-based
    buffer overflow when handling away messages (CAN-2005-2103).
    Furthermore, Daniel Atallah discovered a vulnerability in the handling
    of file transfers (CAN-2005-2102).
  
Impact :

    A remote attacker could create a specially crafted away message
    which, when viewed by the target user, could lead to the execution of
    arbitrary code. Also, an attacker could send a file with a non-UTF8
    filename to a user, which would result in a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200508-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/gaim-1.5.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-im/gaim", unaffected:make_list("ge 1.5.0"), vulnerable:make_list("lt 1.5.0"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gaim");
}