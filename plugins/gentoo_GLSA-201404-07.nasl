#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201404-07.
#
# The advisory text is Copyright (C) 2001-2014 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/2.5/
#

include("compat.inc");

if (description)
{
  script_id(73407);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/06/14 00:01:14 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363);
  script_osvdb_id(104810, 105465);
  script_xref(name:"GLSA", value:"201404-07");

  script_name(english:"GLSA-201404-07 : OpenSSL: Information Disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-201404-07
(OpenSSL: Information Disclosure)

    Multiple vulnerabilities have been found in OpenSSL:
      OpenSSL incorrectly handles memory in the TLS heartbeat extension,
        leading to information disclosure of 64kb per request, possibly
        including private keys (&ldquo;Heartbleed bug&rdquo;, OpenSSL 1.0.1 only,
        CVE-2014-0160).
      The Montgomery ladder implementation of OpenSSL improperly handles
        swap operations (CVE-2014-0076).
  
Impact :

    A remote attacker could exploit these issues to disclose information,
      including private keys or other sensitive information, or perform
      side-channel attacks to obtain ECDSA nonces.
  
Workaround :

    Disabling the tls-heartbeat USE flag (enabled by default) provides a
      workaround for the CVE-2014-0160 issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://heartbleed.com/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-201404-07.xml"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.1g'
    Note: All services using OpenSSL to provide TLS connections have to be
      restarted for the update to take effect. Utilities like
      app-admin/lib_users can aid in identifying programs using OpenSSL.
    As private keys may have been compromised using the Heartbleed attack,
      it is recommended to regenerate them."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat (Heartbleed) Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.1g", "lt 1.0.1", "rge 0.9.8y"), vulnerable:make_list("lt 1.0.1g"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenSSL");
}
