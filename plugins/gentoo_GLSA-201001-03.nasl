#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201001-03.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(44892);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_cve_id("CVE-2008-5498", "CVE-2008-5514", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658", "CVE-2008-5814", "CVE-2008-5844", "CVE-2008-7002", "CVE-2009-0754", "CVE-2009-1271", "CVE-2009-1272", "CVE-2009-2626", "CVE-2009-2687", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3293", "CVE-2009-3546", "CVE-2009-3557", "CVE-2009-3558", "CVE-2009-4017", "CVE-2009-4142", "CVE-2009-4143");
  script_bugtraq_id(32625, 32948, 32958, 33002, 33542, 35440, 36449, 36712, 37079, 37390);
  script_osvdb_id(50480, 50587, 51031, 51477, 52205, 52207, 52486, 53440, 53532, 53574, 55222, 58185, 58186, 58187, 59071, 60434, 60435, 60451, 60654, 61208, 61209);
  script_xref(name:"GLSA", value:"201001-03");

  script_name(english:"GLSA-201001-03 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201001-03
(PHP: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PHP. Please review the
    CVE identifiers referenced below and the associated PHP release notes
    for details.
  
Impact :

    A context-dependent attacker could execute arbitrary code via a
    specially crafted string containing an HTML entity when the mbstring
    extension is enabled. Furthermore a remote attacker could execute
    arbitrary code via a specially crafted GD graphics file.
    A remote attacker could also cause a Denial of Service via a malformed
    string passed to the json_decode() function, via a specially crafted
    ZIP file passed to the php_zip_make_relative_path() function, via a
    malformed JPEG image passed to the exif_read_data() function, or via
    temporary file exhaustion. It is also possible for an attacker to spoof
    certificates, bypass various safe_mode and open_basedir restrictions
    when certain criteria are met, perform Cross-site scripting attacks,
    more easily perform SQL injection attacks, manipulate settings of other
    virtual hosts on the same server via a malicious .htaccess entry when
    running on Apache, disclose memory portions, and write arbitrary files
    via a specially crafted ZIP archive. Some vulnerabilities with unknown
    impact and attack vectors have been reported as well.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200911-03.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201001-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version. As PHP is
    statically linked against a vulnerable version of the c-client library
    when the imap or kolab USE flag is enabled (GLSA 200911-03), users
    should upgrade net-libs/c-client beforehand:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/c-client-2007e'
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.12'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 22, 79, 119, 134, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.2.12"), vulnerable:make_list("lt 5.2.12"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
