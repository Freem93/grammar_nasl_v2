#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200505-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18230);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1431");
  script_osvdb_id(16054);
  script_xref(name:"GLSA", value:"200505-04");

  script_name(english:"GLSA-200505-04 : GnuTLS: Denial of Service vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200505-04
(GnuTLS: Denial of Service vulnerability)

    A vulnerability has been discovered in the record packet parsing
    in the GnuTLS library. Additionally, a flaw was also found in the RSA
    key export functionality.
  
Impact :

    A remote attacker could exploit this vulnerability and cause a
    Denial of Service to any application that utilizes the GnuTLS library.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.gnupg.org/pipermail/gnutls-dev/2005-April/000858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200505-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GnuTLS users should remove the existing installation and
    upgrade to the latest version:
    # emerge --sync
    # emerge --unmerge gnutls
    # emerge --ask --oneshot --verbose net-libs/gnutls
    Due to small API changes with the previous version, please do
    the following to ensure your applications are using the latest GnuTLS
    that you just emerged.
    # revdep-rebuild --soname-regexp libgnutls.so.1[0-1]
    Previously exported RSA keys can be fixed by executing the
    following command on the key files:
    # certtool -k infile outfile"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/28");
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

if (qpkg_check(package:"net-libs/gnutls", unaffected:make_list("ge 1.2.3", "rge 1.0.25"), vulnerable:make_list("lt 1.2.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GnuTLS");
}
