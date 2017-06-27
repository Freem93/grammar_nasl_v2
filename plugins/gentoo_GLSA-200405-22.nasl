#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-22.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14508);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2003-0020", "CVE-2003-0987", "CVE-2003-0993", "CVE-2004-0174");
  script_osvdb_id(12176);
  script_xref(name:"GLSA", value:"200405-22");

  script_name(english:"GLSA-200405-22 : Apache 1.3: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200405-22
(Apache 1.3: Multiple vulnerabilities)

    On 64-bit big-endian platforms, mod_access does not properly parse
    Allow/Deny rules using IP addresses without a netmask which could result in
    failure to match certain IP addresses.
    Terminal escape sequences are not filtered from error logs. This could be
    used by an attacker to insert escape sequences into a terminal emulator
    vulnerable to escape sequences.
    mod_digest does not properly verify the nonce of a client response by using
    a AuthNonce secret. This could permit an attacker to replay the response of
    another website. This does not affect mod_auth_digest.
    On certain platforms there is a starvation issue where listening sockets
    fails to handle short-lived connection on a rarely-accessed listening
    socket. This causes the child to hold the accept mutex and block out new
    connections until another connection arrives on the same rarely-accessed
    listening socket thus leading to a denial of service.
  
Impact :

    These vulnerabilities could lead to attackers bypassing intended access
    restrictions, denial of service, and possibly execution of arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest stable version of Apache 1.3.
    # emerge sync
    # emerge -pv '>=www-servers/apache-1.3.31'
    # emerge '>=www-servers/apache-1.3.31'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 1.3.31"), vulnerable:make_list("lt 1.3.31"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache 1.3");
}
