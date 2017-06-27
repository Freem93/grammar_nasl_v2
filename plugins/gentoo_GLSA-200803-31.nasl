#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-31.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31671);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-5894", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_osvdb_id(43341, 43342, 43343, 43345, 43346);
  script_xref(name:"GLSA", value:"200803-31");

  script_name(english:"GLSA-200803-31 : MIT Kerberos 5: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200803-31
(MIT Kerberos 5: Multiple vulnerabilities)

    Two vulnerabilities were found in the Kerberos 4 support in
    KDC: A global variable is not set for some incoming message types,
    leading to a NULL pointer dereference or a double free()
    (CVE-2008-0062) and unused portions of a buffer are not properly
    cleared when generating an error message, which results in stack
    content being contained in a reply (CVE-2008-0063).
    Jeff
    Altman (Secure Endpoints) discovered a buffer overflow in the RPC
    library server code, used in the kadmin server, caused when too many
    file descriptors are opened (CVE-2008-0947).
    Venustech AD-LAB
    discovered multiple vulnerabilities in the GSSAPI library: usage of a
    freed variable in the gss_indicate_mechs() function (CVE-2007-5901) and
    a double free() vulnerability in the gss_krb5int_make_seal_token_v3()
    function (CVE-2007-5971).
  
Impact :

    The first two vulnerabilities can be exploited by a remote
    unauthenticated attacker to execute arbitrary code on the host running
    krb5kdc, compromise the Kerberos key database or cause a Denial of
    Service. These bugs can only be triggered when Kerberos 4 support is
    enabled.
    The RPC related vulnerability can be exploited by a remote
    unauthenticated attacker to crash kadmind, and theoretically execute
    arbitrary code with root privileges or cause database corruption. This
    bug can only be triggered in configurations that allow large numbers of
    open file descriptors in a process.
    The GSSAPI vulnerabilities could be exploited by a remote attacker to
    cause Denial of Service conditions or possibly execute arbitrary code.
  
Workaround :

    Kerberos 4 support can be disabled via disabling the 'krb4' USE flag
    and recompiling the ebuild, or setting 'v4_mode=none' in the
    [kdcdefaults] section of /etc/krb5/kdc.conf. This will only work around
    the KDC related vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MIT Kerberos 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-crypt/mit-krb5-1.6.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mit-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/26");
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

if (qpkg_check(package:"app-crypt/mit-krb5", unaffected:make_list("ge 1.6.3-r1"), vulnerable:make_list("lt 1.6.3-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MIT Kerberos 5");
}
