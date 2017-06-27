#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14553);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-1438");
  script_osvdb_id(8239);
  script_xref(name:"GLSA", value:"200407-20");

  script_name(english:"GLSA-200407-20 : Subversion: Vulnerability in mod_authz_svn");
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
"The remote host is affected by the vulnerability described in GLSA-200407-20
(Subversion: Vulnerability in mod_authz_svn)

    Users with write access to part of a Subversion repository may bypass
    read restrictions on any part of that repository. This can be done
    using an 'svn copy' command to copy the portion of a repository the
    user wishes to read into an area where they have write access.
    Since copies are versioned, any such copy attempts will be readily
    apparent.
  
Impact :

    This is a low-risk vulnerability. It affects only users of Subversion
    who are running servers inside Apache and using mod_authz_svn.
    Additionally, this vulnerability may be exploited only by users with
    write access to some portion of a repository.
  
Workaround :

    Keep sensitive content separated into different Subversion
    repositories, or disable the Apache Subversion server and use svnserve
    instead."
  );
  # http://svn.collab.net/repos/svn/tags/1.0.6/CHANGES
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/repos/asf/subversion/branches/1.0.x/CHANGES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Subversion users should upgrade to the latest available version:
    # emerge sync
    # emerge -pv '>=dev-util/subversion-1.0.6'
    # emerve '>=dev-util/subversion-1.0.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/26");
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

if (qpkg_check(package:"dev-util/subversion", unaffected:make_list("ge 1.0.6"), vulnerable:make_list("le 1.0.4-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Subversion");
}
