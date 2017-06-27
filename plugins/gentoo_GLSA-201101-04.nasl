#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201101-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(51534);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/13 14:19:44 $");

  script_cve_id("CVE-2010-1512");
  script_osvdb_id(64592);
  script_xref(name:"GLSA", value:"201101-04");

  script_name(english:"GLSA-201101-04 : aria2: Directory traversal");
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
"The remote host is affected by the vulnerability described in GLSA-201101-04
(aria2: Directory traversal)

    A directory traversal vulnerability was discovered in aria2.
  
Impact :

    A remote attacker could entice a user to download from a specially
    crafted metalink file, resulting in the creation of arbitrary files.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201101-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All aria2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/aria2-1.9.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aria2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/aria2", unaffected:make_list("ge 1.9.3"), vulnerable:make_list("lt 1.9.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aria2");
}
