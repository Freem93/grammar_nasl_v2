#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14564);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-1701", "CVE-2004-1702");
  script_osvdb_id(8406, 14664);
  script_xref(name:"GLSA", value:"200408-08");

  script_name(english:"GLSA-200408-08 : Cfengine: RSA Authentication Heap Corruption");
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
"The remote host is affected by the vulnerability described in GLSA-200408-08
(Cfengine: RSA Authentication Heap Corruption)

    Two vulnerabilities have been found in cfservd. One is a buffer
    overflow in the AuthenticationDialogue function and the other is a
    failure to check the proper return value of the ReceiveTransaction
    function.
  
Impact :

    An attacker could use the buffer overflow to execute arbitrary code
    with the permissions of the user running cfservd, which is usually the
    root user. However, before such an attack could be mounted, the
    IP-based ACL would have to be bypassed. With the second vulnerability,
    an attacker could cause a denial of service attack.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Cfengine. (It should be
    noted that disabling cfservd will work around this particular problem.
    However, in many cases, doing so will cripple your Cfengine setup.
    Upgrading is strongly recommended.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.coresecurity.com/common/showdoc.php?idx=387&idxseccion=10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Cfengine users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=net-misc/cfengine-2.1.8'
    # emerge '>=net-misc/cfengine-2.1.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cfengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/09");
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

if (qpkg_check(package:"net-misc/cfengine", unaffected:make_list("ge 2.1.8", "lt 2.0.0"), vulnerable:make_list("le 2.1.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cfengine");
}
