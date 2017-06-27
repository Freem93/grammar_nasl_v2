#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17978);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0468", "CVE-2005-0469");
  script_osvdb_id(15093, 15094);
  script_xref(name:"GLSA", value:"200504-04");

  script_name(english:"GLSA-200504-04 : mit-krb5: Multiple buffer overflows in telnet client");
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
"The remote host is affected by the vulnerability described in GLSA-200504-04
(mit-krb5: Multiple buffer overflows in telnet client)

    A buffer overflow has been identified in the env_opt_add()
    function, where a response requiring excessive escaping can cause a
    heap-based buffer overflow. Another issue has been identified in the
    slc_add_reply() function, where a large number of SLC commands can
    overflow a fixed size buffer.
  
Impact :

    Successful exploitation would require a vulnerable user to connect
    to an attacker-controlled telnet host, potentially executing arbitrary
    code with the permissions of the telnet user on the client.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2005-001-telnet.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf1e4bc6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All mit-krb5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-crypt/mit-krb5-1.3.6-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mit-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/28");
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

if (qpkg_check(package:"app-crypt/mit-krb5", unaffected:make_list("ge 1.3.6-r2"), vulnerable:make_list("lt 1.3.6-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mit-krb5");
}
