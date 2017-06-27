#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14478);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0180", "CVE-2004-0405");
  script_xref(name:"GLSA", value:"200404-13");

  script_name(english:"GLSA-200404-13 : CVS Server and Client Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200404-13
(CVS Server and Client Vulnerabilities)

    There are two vulnerabilities in CVS; one in the server and one in the
    client. The server vulnerability allows a malicious client to request
    the contents of any RCS file to which the server has permission, even
    those not located under $CVSROOT. The client vulnerability allows a
    malicious server to overwrite files on the client machine anywhere the
    client has permissions.
  
Impact :

    Arbitrary files may be read or written on CVS clients and servers by
    anybody with access to the CVS tree.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest stable version of CVS."
  );
  # http://ccvs.cvshome.org/source/browse/ccvs/NEWS?rev=1.116.2.92&content-type=text/x-cvsweb-markup
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3f99663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CVS users should upgrade to the latest stable version.
    # emerge sync
    # emerge -pv '>=dev-util/cvs-1.11.15'
    # emerge '>=dev-util/cvs-1.11.15'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/14");
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

if (qpkg_check(package:"dev-util/cvs", unaffected:make_list("ge 1.11.15"), vulnerable:make_list("le 1.11.14"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-util/cvs");
}
