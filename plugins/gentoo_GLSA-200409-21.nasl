#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-21.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14766);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/08/15 14:21:39 $");

  script_cve_id("CVE-2004-0747", "CVE-2004-0748", "CVE-2004-0751", "CVE-2004-0786", "CVE-2004-0809");
  script_osvdb_id(9742, 9948, 9991, 9994);
  script_xref(name:"GLSA", value:"200409-21");

  script_name(english:"GLSA-200409-21 : Apache 2, mod_dav: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200409-21
(Apache 2, mod_dav: Multiple vulnerabilities)

    A potential infinite loop has been found in the input filter of mod_ssl
    (CAN-2004-0748) as well as a possible segmentation fault in the
    char_buffer_read function if reverse proxying to a SSL server is being used
    (CAN-2004-0751). Furthermore, mod_dav, as shipped in Apache httpd 2 or
    mod_dav 1.0.x for Apache 1.3, contains a NULL pointer dereference which can
    be triggered remotely (CAN-2004-0809). The third issue is an input
    validation error found in the IPv6 URI parsing routines within the apr-util
    library (CAN-2004-0786). Additionally a possible buffer overflow has been
    reported when expanding environment variables during the parsing of
    configuration files (CAN-2004-0747).
  
Impact :

    A remote attacker could cause a Denial of Service either by aborting a SSL
    connection in a special way, resulting in CPU consumption, by exploiting
    the segmentation fault in mod_ssl or the mod_dav flaw. A remote attacker
    could also crash a httpd child process by sending a specially crafted URI.
    The last vulnerability could be used by a local user to gain the privileges
    of a httpd child, if the server parses a carefully prepared .htaccess file.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache 2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=www-servers/apache-2.0.51'
    # emerge '>=www-servers/apache-2.0.51'
    All mod_dav users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=net-www/mod_dav-1.0.3-r2'
    # emerge '>=net-www/mod_dav-1.0.3-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_dav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/02");
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

if (qpkg_check(package:"net-www/mod_dav", unaffected:make_list("ge 1.0.3-r2"), vulnerable:make_list("le 1.0.3-r1"))) flag++;
if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 2.0.51", "lt 2.0"), vulnerable:make_list("lt 2.0.51"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache 2 / mod_dav");
}
