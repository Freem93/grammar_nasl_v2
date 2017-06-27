#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19200);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-2069");
  script_bugtraq_id(14126);
  script_osvdb_id(17692);
  script_xref(name:"GLSA", value:"200507-13");

  script_name(english:"GLSA-200507-13 : pam_ldap and nss_ldap: Plain text authentication leak");
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
"The remote host is affected by the vulnerability described in GLSA-200507-13
(pam_ldap and nss_ldap: Plain text authentication leak)

    Rob Holland of the Gentoo Security Audit Team discovered that
    pam_ldap and nss_ldap fail to use TLS for referred connections if they
    are referred to a master after connecting to a slave, regardless of the
    'ssl start_tls' ldap.conf setting.
  
Impact :

    An attacker could sniff passwords or other sensitive information
    as the communication is not encrypted.
  
Workaround :

    pam_ldap and nss_ldap can be set to force the use of SSL instead
    of TLS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All pam_ldap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-auth/pam_ldap-178-r1'
    All nss_ldap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose sys-auth/nss_ldap"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nss_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pam_ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/21");
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

if (qpkg_check(package:"sys-auth/pam_ldap", unaffected:make_list("ge 178-r1"), vulnerable:make_list("lt 178-r1"))) flag++;
if (qpkg_check(package:"sys-auth/nss_ldap", unaffected:make_list("ge 239-r1", "rge 226-r1"), vulnerable:make_list("lt 239-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam_ldap and nss_ldap");
}
