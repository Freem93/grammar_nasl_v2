#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14651);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0832");
  script_osvdb_id(9551);
  script_xref(name:"GLSA", value:"200409-04");

  script_name(english:"GLSA-200409-04 : Squid: Denial of service when using NTLM authentication");
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
"The remote host is affected by the vulnerability described in GLSA-200409-04
(Squid: Denial of service when using NTLM authentication)

    Squid 2.5.x versions contain a bug in the functions ntlm_fetch_string()
    and ntlm_get_string() which lack checking the int32_t offset 'o' for
    negative values.
  
Impact :

    A remote attacker could cause a denial of service situation by sending
    certain malformed NTLMSSP packets if NTLM authentication is enabled.
  
Workaround :

    Disable NTLM authentication by removing any 'auth_param ntlm program
    ...' directives from squid.conf or use ntlm_auth from Samba-3.x."
  );
  # http://www1.uk.squid-cache.org/squid/Versions/v2/2.5/bugs/#squid-2.5.STABLE6-ntlm_fetch_string
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b945f310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Squid users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=net-www/squid-2.5.6-r2'
    # emerge '>=net-www/squid-2.5.6-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-proxy/squid", unaffected:make_list("ge 2.5.6-r2", "lt 2.5"), vulnerable:make_list("le 2.5.6-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Squid");
}
