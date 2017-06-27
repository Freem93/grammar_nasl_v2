#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-15.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14548);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_bugtraq_id(10517);
  script_xref(name:"GLSA", value:"200407-15");

  script_name(english:"GLSA-200407-15 : Opera: Multiple spoofing vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200407-15
(Opera: Multiple spoofing vulnerabilities)

    Opera fails to remove illegal characters from an URI of a link and to check
    that the target frame of a link belongs to the same website as the link.
    Opera also updates the address bar before loading a page. Additionally,
    Opera contains a certificate verification problem.
  
Impact :

    These vulnerabilities could allow an attacker to impersonate legitimate
    websites to steal sensitive information from users. This could be done by
    obfuscating the real URI of a link or by injecting a malicious frame into
    an arbitrary frame of another browser window.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/11978/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/12028/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/linux/changelogs/753/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=www-client/opera-7.53'
    # emerge '>=www-client/opera-7.53'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 7.53"), vulnerable:make_list("le 7.52"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Opera");
}
