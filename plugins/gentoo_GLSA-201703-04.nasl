#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201703-04.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(99011);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");

  script_cve_id("CVE-2017-2629");
  script_xref(name:"GLSA", value:"201703-04");

  script_name(english:"GLSA-201703-04 : cURL: Certificate validation error");
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
"The remote host is affected by the vulnerability described in GLSA-201703-04
(cURL: Certificate validation error)

    cURL and applications linked against libcurl support &ldquo;OCSP
      stapling&rdquo;, also known as the TLS Certificate Status Request extension
      (using the CURLOPT_SSL_VERIFYSTATUS option). When telling cURL to use
      this feature, it uses that TLS extension to ask for a fresh proof of the
      server&rsquo;s certificate&rsquo;s validity. If the server doesn&rsquo;t support the
      extension, or fails to provide said proof, cURL is expected to return an
      error.
      Due to a coding mistake, the code that checks for a test success or
      failure, ends up always thinking there&rsquo;s valid proof, even when there
      is none or if the server doesn&rsquo;t support the TLS extension in question.
  
Impact :

    Due to the error, a user maybe does not detect when a server&rsquo;s
      certificate goes invalid or otherwise be mislead that the server is in a
      better shape than it is in reality.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201703-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All cURL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/curl-7.53.0'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/curl", unaffected:make_list("ge 7.53.0"), vulnerable:make_list("lt 7.53.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cURL");
}
