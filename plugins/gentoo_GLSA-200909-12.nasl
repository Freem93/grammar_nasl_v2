#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200909-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(40959);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 14:12:00 $");

  script_cve_id("CVE-2009-3050");
  script_bugtraq_id(35727);
  script_osvdb_id(55840);
  script_xref(name:"GLSA", value:"200909-12");

  script_name(english:"GLSA-200909-12 : HTMLDOC: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200909-12
(HTMLDOC: User-assisted execution of arbitrary code)

    ANTHRAX666 reported an insecure call to the sscanf() function in the
    set_page_size() function in htmldoc/util.cxx. Nico Golde of the Debian
    Security Team found two more insecure calls in the write_type1()
    function in htmldoc/ps-pdf.cxx and the htmlLoadFontWidths() function in
    htmldoc/htmllib.cxx.
  
Impact :

    A remote attacker could entice a user to process a specially crafted
    HTML file using htmldoc, possibly resulting in the execution of
    arbitrary code with the privileges of the user running the application.
    NOTE: Additional vectors via specially crafted AFM font metric files do
    not cross trust boundaries, as the files can only be modified by
    privileged users.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200909-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All HTMLDOC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/htmldoc-1.8.27-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:htmldoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/htmldoc", unaffected:make_list("ge 1.8.27-r1"), vulnerable:make_list("lt 1.8.27-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "HTMLDOC");
}
