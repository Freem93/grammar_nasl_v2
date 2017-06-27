#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200812-16.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35108);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-4577", "CVE-2008-4578", "CVE-2008-4870", "CVE-2008-4907");
  script_bugtraq_id(31587);
  script_xref(name:"GLSA", value:"200812-16");

  script_name(english:"GLSA-200812-16 : Dovecot: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200812-16
(Dovecot: Multiple vulnerabilities)

    Several vulnerabilities were found in Dovecot:
    The 'k'
    right in the acl_plugin does not work as expected (CVE-2008-4577,
    CVE-2008-4578)
    The dovecot.conf is world-readable, providing
    improper protection for the ssl_key_password setting
    (CVE-2008-4870)
    A permanent Denial of Service with broken mail
    headers is possible (CVE-2008-4907)
  
Impact :

    These vulnerabilities might allow a remote attacker to cause a Denial
    of Service, to circumvent security restrictions or allow local
    attackers to disclose the passphrase of the SSL private key.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200812-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Dovecot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/dovecot-1.1.7-r1'
    Users should be aware that dovecot.conf will still be world-readable
    after the update. If employing ssl_key_password, it should not be used
    in dovecot.conf but in a separate file which should be included with
    'include_try'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-mail/dovecot", unaffected:make_list("ge 1.1.7-r1"), vulnerable:make_list("lt 1.1.7-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Dovecot");
}
