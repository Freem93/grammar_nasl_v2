#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-30.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31636);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_cve_id("CVE-2008-1383");
  script_osvdb_id(43479);
  script_xref(name:"GLSA", value:"200803-30");

  script_name(english:"GLSA-200803-30 : ssl-cert eclass: Certificate disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-200803-30
(ssl-cert eclass: Certificate disclosure)

    Robin Johnson reported that the docert() function provided by
    ssl-cert.eclass can be called by source building stages of an ebuild,
    such as src_compile() or src_install(), which will result in the
    generated SSL keys being included inside binary packages (binpkgs).
  
Impact :

    A local attacker could recover the SSL keys from publicly readable
    binary packages when 'emerge' is called with the '--buildpkg
    (-b)' or '--buildpkgonly (-B)' option. Remote attackers can
    recover these keys if the packages are served to a network. Binary
    packages built using 'quickpkg' are not affected.
  
Workaround :

    Do not use pre-generated SSL keys, but use keys that were generated
    using a different Certificate Authority."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrading to newer versions of the above packages will neither remove
    possibly compromised SSL certificates, nor old binary packages. Please
    remove the certificates installed by Portage, and then emerge an
    upgrade to the package.
    All Conserver users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/conserver-8.1.16'
    All Postfix 2.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.4.6-r2'
    All Postfix 2.3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.3.8-r1'
    All Postfix 2.2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.2.11-r1'
    All Netkit FTP Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-ftp/netkit-ftpd-0.17-r7'
    All ejabberd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/ejabberd-1.1.3'
    All UnrealIRCd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-irc/unrealircd-3.2.7-r2'
    All Cyrus IMAP Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/cyrus-imapd-2.3.9-r1'
    All Dovecot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/dovecot-1.0.10'
    All stunnel 4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/stunnel-4.21'
    All InterNetNews users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-nntp/inn-2.4.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:conserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ejabberd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:inn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:netkit-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:stunnel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:unrealircd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-nntp/inn", unaffected:make_list("ge 2.4.3-r1"), vulnerable:make_list("lt 2.4.3-r1"))) flag++;
if (qpkg_check(package:"net-mail/cyrus-imapd", unaffected:make_list("ge 2.3.9-r1"), vulnerable:make_list("lt 2.3.9-r1"))) flag++;
if (qpkg_check(package:"app-admin/conserver", unaffected:make_list("ge 8.1.16"), vulnerable:make_list("lt 8.1.16"))) flag++;
if (qpkg_check(package:"net-misc/stunnel", unaffected:make_list("ge 4.21-r1", "lt 4.0"), vulnerable:make_list("lt 4.21-r1"))) flag++;
if (qpkg_check(package:"net-irc/unrealircd", unaffected:make_list("ge 3.2.7-r2"), vulnerable:make_list("lt 3.2.7-r2"))) flag++;
if (qpkg_check(package:"mail-mta/postfix", unaffected:make_list("ge 2.4.6-r2", "rge 2.3.8-r1", "rge 2.2.11-r1"), vulnerable:make_list("lt 2.4.6-r2"))) flag++;
if (qpkg_check(package:"net-mail/dovecot", unaffected:make_list("ge 1.0.10"), vulnerable:make_list("lt 1.0.10"))) flag++;
if (qpkg_check(package:"net-ftp/netkit-ftpd", unaffected:make_list("ge 0.17-r7"), vulnerable:make_list("lt 0.17-r7"))) flag++;
if (qpkg_check(package:"net-im/ejabberd", unaffected:make_list("ge 1.1.3"), vulnerable:make_list("lt 1.1.3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ssl-cert eclass");
}
