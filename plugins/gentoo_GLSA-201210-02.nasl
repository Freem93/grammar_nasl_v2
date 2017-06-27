#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201210-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(62632);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/13 14:19:45 $");

  script_cve_id("CVE-2010-0668", "CVE-2010-0669", "CVE-2010-0717", "CVE-2010-0828", "CVE-2010-1238", "CVE-2010-2487", "CVE-2010-2969", "CVE-2010-2970", "CVE-2011-1058");
  script_bugtraq_id(38023, 39110, 39327, 40549, 46476);
  script_osvdb_id(62043, 62654, 62655, 63362, 63619, 65065, 66894, 66895, 66896, 66897, 66898, 66899, 66900, 66901, 66902, 66903, 66904, 66905, 66906, 66907, 66908, 71025);
  script_xref(name:"GLSA", value:"201210-02");

  script_name(english:"GLSA-201210-02 : MoinMoin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201210-02
(MoinMoin: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MoinMoin. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    These vulnerabilities in MoinMoin allow remote users to inject arbitrary
      web script or HTML, to obtain sensitive information and to bypass the
      textcha protection mechanism. There are several other unknown impacts and
      attack vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201210-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MoinMoin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/moinmoin-1.9.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:moinmoin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/moinmoin", unaffected:make_list("ge 1.9.4"), vulnerable:make_list("lt 1.9.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MoinMoin");
}
