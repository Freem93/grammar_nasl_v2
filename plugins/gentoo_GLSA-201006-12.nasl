#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201006-12.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(46779);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-2666", "CVE-2010-0562");
  script_bugtraq_id(38088);
  script_osvdb_id(56855, 62114);
  script_xref(name:"GLSA", value:"201006-12");

  script_name(english:"GLSA-201006-12 : Fetchmail: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201006-12
(Fetchmail: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in Fetchmail:
    The sdump() function might trigger a heap-based buffer overflow
    during the escaping of non-printable characters with the high bit set
    from an X.509 certificate (CVE-2010-0562).
    The vendor reported
    that Fetchmail does not properly handle Common Name (CN) fields in
    X.509 certificates that contain an ASCII NUL character. Specifically,
    the processing of such fields is stopped at the first occurrence of a
    NUL character. This type of vulnerability was recently discovered by
    Dan Kaminsky and Moxie Marlinspike (CVE-2009-2666).
  
Impact :

    A remote attacker could entice a user to connect with Fetchmail to a
    specially crafted SSL-enabled server in verbose mode, possibly
    resulting in the execution of arbitrary code with the privileges of the
    user running the application. NOTE: The issue is only existent on
    platforms on which char is signed.
    Furthermore, a remote attacker might employ a specially crafted X.509
    certificate, containing a NUL character in the Common Name field to
    conduct man-in-the-middle attacks on SSL connections made using
    Fetchmail.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201006-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Fetchmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/fetchmail-6.3.14'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-mail/fetchmail", unaffected:make_list("ge 6.3.14"), vulnerable:make_list("lt 6.3.14"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Fetchmail");
}
