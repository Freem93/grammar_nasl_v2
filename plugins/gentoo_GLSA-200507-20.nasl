#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19282);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-2317");
  script_osvdb_id(18005);
  script_xref(name:"GLSA", value:"200507-20");

  script_name(english:"GLSA-200507-20 : Shorewall: Security policy bypass");
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
"The remote host is affected by the vulnerability described in GLSA-200507-20
(Shorewall: Security policy bypass)

    Shorewall fails to enforce security policies if configured with
    'MACLIST_DISPOSITION' set to 'ACCEPT' or 'MACLIST_TTL' set to a value
    greater or equal to 0.
  
Impact :

    A client authenticated by MAC address filtering could bypass all
    security policies, possibly allowing him to gain access to restricted
    services. The default installation has MACLIST_DISPOSITION=REJECT and
    MACLIST_TTL=(blank) (equivalent to 0). This can be checked by looking
    at the settings in /etc/shorewall/shorewall.conf
  
Workaround :

    Set 'MACLIST_TTL' to '0' and 'MACLIST_DISPOSITION' to 'REJECT' in the
    Shorewall configuration file (usually /etc/shorewall/shorewall.conf)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.shorewall.net/News.htm#20050717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Shorewall users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-firewall/shorewall"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:shorewall");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/17");
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

if (qpkg_check(package:"net-firewall/shorewall", unaffected:make_list("ge 2.4.2"), vulnerable:make_list("le 2.4.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Shorewall");
}
