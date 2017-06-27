#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200911-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(42415);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2009-3236", "CVE-2009-3237");
  script_osvdb_id(58107, 58108, 58109);
  script_xref(name:"GLSA", value:"200911-01");

  script_name(english:"GLSA-200911-01 : Horde: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200911-01
(Horde: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Horde:
    Stefan Esser of Sektion1 reported an error within the form library
    when handling image form fields (CVE-2009-3236).
    Martin
    Geisler and David Wharton reported that an error exists in the MIME
    viewer library when viewing unknown text parts and the preferences
    system in services/prefs.php when handling number preferences
    (CVE-2009-3237).
  
Impact :

    A remote authenticated attacker could exploit these vulnerabilities to
    overwrite arbitrary files on the server, provided that the user has
    write permissions. A remote authenticated attacker could conduct
    Cross-Site Scripting attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200911-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Horde users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-3.3.5'
    All Horde webmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-webmail-1.2.4'
    All Horde groupware users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-groupware-1.2.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-groupware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-webmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/horde-webmail", unaffected:make_list("ge 1.2.4"), vulnerable:make_list("lt 1.2.4"))) flag++;
if (qpkg_check(package:"www-apps/horde", unaffected:make_list("ge 3.3.5"), vulnerable:make_list("lt 3.3.5"))) flag++;
if (qpkg_check(package:"www-apps/horde-groupware", unaffected:make_list("ge 1.2.4"), vulnerable:make_list("lt 1.2.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Horde");
}
