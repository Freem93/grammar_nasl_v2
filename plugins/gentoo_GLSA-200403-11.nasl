#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200403-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14462);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0189");
  script_xref(name:"GLSA", value:"200403-11");

  script_name(english:"GLSA-200403-11 : Squid ACL [url_regex] bypass vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200403-11
(Squid ACL [url_regex] bypass vulnerability)

    A bug in Squid allows users to bypass certain access controls by passing a
    URL containing '%00' which exploits the Squid decoding function.
    This may insert a NUL character into decoded URLs, which may allow users to
    bypass url_regex access control lists that are enforced upon them.
    In such a scenario, Squid will insert a NUL character after
    the'%00' and it will make a comparison between the URL to the end
    of the NUL character rather than the contents after it: the comparison does
    not result in a match, and the user's request is not denied.
  
Impact :

    Restricted users may be able to bypass url_regex access control lists that
    are enforced upon them which may cause unwanted network traffic as well as
    a route for other possible exploits. Users of Squid 2.5STABLE4 and below
    who require the url_regex features are recommended to upgrade to 2.5STABLE5
    to maintain the security of their infrastructure.
  
Workaround :

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of Squid."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squid-cache.org/Advisories/SQUID-2004_1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200403-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Squid can be updated as follows:
    # emerge sync
    # emerge -pv '>=net-proxy/squid-2.5.5'
    # emerge '>=net-proxy/squid-2.5.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"net-proxy/squid", unaffected:make_list("ge 2.5.5"), vulnerable:make_list("lt 2.5.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-proxy/squid");
}
