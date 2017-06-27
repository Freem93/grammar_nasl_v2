#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200712-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(29292);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 14:04:24 $");

  script_cve_id("CVE-2007-5934");
  script_osvdb_id(42107);
  script_xref(name:"GLSA", value:"200712-05");

  script_name(english:"GLSA-200712-05 : PEAR::MDB2: Information disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-200712-05
(PEAR::MDB2: Information disclosure)

    priyadi discovered that the request to store a URL string as a LOB is
    treated as a request to retrieve and store the contents of the URL.
  
Impact :

    If an application using PEAR::MDB2 allows input of LOB values via a web
    form, remote attackers could use the application as an indirect proxy
    or obtain sensitive information, including 'file://' URLs local to the
    web server.
  
Workaround :

    As a workaround, manually filter input before storing it as a LOB in
    PEAR::MDB2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200712-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PEAR::MDB2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/PEAR-MDB2-2.5.0_alpha1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:PEAR-MDB2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-php/PEAR-MDB2", unaffected:make_list("ge 2.5.0_alpha1"), vulnerable:make_list("lt 2.5.0_alpha1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PEAR::MDB2");
}
