#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201209-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(62237);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2012-1033", "CVE-2012-1667", "CVE-2012-3817", "CVE-2012-3868", "CVE-2012-4244");
  script_bugtraq_id(51898, 53772, 54658, 54659, 55522);
  script_osvdb_id(78916, 82609, 84228, 84229, 85417);
  script_xref(name:"GLSA", value:"201209-04");

  script_name(english:"GLSA-201209-04 : BIND: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201209-04
(BIND: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in BIND:
      Domain names are not properly revoked due to an error in the cache
        update policy (CVE-2012-1033).
      BIND accepts records with zero-length RDATA fields (CVE-2012-1667).
      An assertion failure from the failing-query cache could occur when
        DNSSEC validation is enabled (CVE-2012-3817).
      A memory leak may occur under high TCP query loads (CVE-2012-3868).
      An assertion error can occur when a query is performed for a record
        with RDATA greater than 65535 bytes (CVE-2012-4244).
  
Impact :

    A remote attacker may be able to cause a Denial of Service condition or
      keep domain names resolvable after it has been deleted from registration.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201209-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All BIND users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-dns/bind-9.9.1_p3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-dns/bind", unaffected:make_list("ge 9.9.1_p3"), vulnerable:make_list("lt 9.9.1_p3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BIND");
}
