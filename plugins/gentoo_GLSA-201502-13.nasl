#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201502-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(81396);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/21 13:46:13 $");

  script_cve_id("CVE-2014-7923", "CVE-2014-7924", "CVE-2014-7925", "CVE-2014-7926", "CVE-2014-7927", "CVE-2014-7928", "CVE-2014-7929", "CVE-2014-7930", "CVE-2014-7931", "CVE-2014-7932", "CVE-2014-7933", "CVE-2014-7934", "CVE-2014-7935", "CVE-2014-7936", "CVE-2014-7937", "CVE-2014-7938", "CVE-2014-7939", "CVE-2014-7940", "CVE-2014-7941", "CVE-2014-7942", "CVE-2014-7943", "CVE-2014-7944", "CVE-2014-7945", "CVE-2014-7946", "CVE-2014-7947", "CVE-2014-7948", "CVE-2014-9646", "CVE-2014-9647", "CVE-2014-9648", "CVE-2015-1205", "CVE-2015-1209", "CVE-2015-1210", "CVE-2015-1211", "CVE-2015-1212", "CVE-2015-1346", "CVE-2015-1359", "CVE-2015-1360", "CVE-2015-1361");
  script_osvdb_id(117824);
  script_xref(name:"GLSA", value:"201502-13");

  script_name(english:"GLSA-201502-13 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201502-13
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker may be able to cause a Denial of Service condition,
      gain privileges via a filesystem: URI, or have other unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201502-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-40.0.2214.111'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 40.0.2214.111"), vulnerable:make_list("lt 40.0.2214.111"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
