#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200403-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14455);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0113");
  script_bugtraq_id(9933);
  script_xref(name:"GLSA", value:"200403-04");

  script_name(english:"GLSA-200403-04 : Multiple security vulnerabilities in Apache 2");
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
"The remote host is affected by the vulnerability described in GLSA-200403-04
(Multiple security vulnerabilities in Apache 2)

    Three vulnerabilities were found:
    A memory leak in ssl_engine_io.c for mod_ssl in Apache 2.0.48 and below
    allows remote attackers to cause a denial of service attack via plain
    HTTP requests to the SSL port of an SSL-enabled server.
    Apache fails to filter terminal escape sequences from error logs that
    begin with the ASCII (0x1B) sequence and are followed by a  series of
    arguments. If a remote attacker could inject escape sequences into an
    Apache error log, the attacker could take advantages of weaknesses in
    various terminal emulators, launching attacks against remote users
    including further denial of service attacks, file modification, and the
    execution of arbitrary commands.
    The Apache mod_disk_cache has been found to be vulnerable to a weakness
    that allows attackers to gain access to authentication credentials
    through the issue of caching HTTP hop-by-hop headers which would
    contain plaintext user passwords. There is no available resolution for
    this issue yet.
  
Impact :

    No special privileges are required for these vulnerabilities. As a
    result, all users are recommended to upgrade their Apache
    installations.
  
Workaround :

    There is no immediate workaround; a software upgrade is required. There
    is no workaround for the mod_disk_cache issue; users are recommended to
    disable the feature on their servers until a patched version is
    released."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apache.org/dist/httpd/Announcement2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200403-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users are urged to upgrade to Apache 2.0.49:
    # emerge sync
    # emerge -pv '>=www-servers/apache-2.0.49'
    # emerge '>=www-servers/apache-2.0.49'
    # ** IMPORTANT **
    # If you are migrating from Apache 2.0.48-r1 or earlier versions,
    # it is important that the following directories are removed.
    # The following commands should cause no data loss since these
    # are symbolic links.
    # rm /etc/apache2/lib /etc/apache2/logs /etc/apache2/modules
    # rm /etc/apache2/modules
    # ** ** ** ** **
    # ** ALSO NOTE **
    # Users who use mod_disk_cache should edit their Apache
    # configuration and disable mod_disk_cache."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("eq 1.3*", "ge 2.0.49"), vulnerable:make_list("le 2.0.48"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "www-servers/apache");
}
