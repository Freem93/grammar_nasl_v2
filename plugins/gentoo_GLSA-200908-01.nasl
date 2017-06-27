#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200908-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(40462);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/08/24 13:49:14 $");

  script_cve_id("CVE-2009-0368", "CVE-2009-1603");
  script_bugtraq_id(33922, 34884);
  script_osvdb_id(52827, 52828, 54499);
  script_xref(name:"GLSA", value:"200908-01");

  script_name(english:"GLSA-200908-01 : OpenSC: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200908-01
(OpenSC: Multiple vulnerabilities)

    Multiple vulnerabilities were found in OpenSC:
    b.badrignans discovered that OpenSC incorrectly initialises private
    data objects (CVE-2009-0368).
    Miquel Comas Marti discovered
    that src/tools/pkcs11-tool.c in pkcs11-tool in OpenSC 0.11.7, when used
    with unspecified third-party PKCS#11 modules, generates RSA keys with
    incorrect public exponents (CVE-2009-1603).
  
Impact :

    The first vulnerability allows physically proximate attackers to bypass
    intended PIN requirements and read private data objects. The second
    vulnerability allows attackers to read the cleartext form of messages
    that were intended to be encrypted.
    NOTE: Smart cards which were initialised using an affected version of
    OpenSC need to be modified or re-initialised. See the vendor's advisory
    for details.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.opensc-project.org/pipermail/opensc-announce/2009-February/000023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?222f0459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200908-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/opensc-0.11.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opensc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/03");
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

if (qpkg_check(package:"dev-libs/opensc", unaffected:make_list("ge 0.11.8"), vulnerable:make_list("lt 0.11.8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenSC");
}
