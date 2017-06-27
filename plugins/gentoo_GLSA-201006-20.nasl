#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201006-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(46809);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2008-7220", "CVE-2009-2346", "CVE-2009-2726", "CVE-2009-3727", "CVE-2009-4055");
  script_bugtraq_id(36015, 36275, 36926, 37153);
  script_osvdb_id(46312, 56991, 57762, 59697, 60569);
  script_xref(name:"GLSA", value:"201006-20");

  script_name(english:"GLSA-201006-20 : Asterisk: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201006-20
(Asterisk: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in Asterisk:
    Nick Baggott reported that Asterisk does not properly process
    overly long ASCII strings in various packets (CVE-2009-2726).
    Noam Rathaus and Blake Cornell reported a flaw in the IAX2 protocol
    implementation (CVE-2009-2346).
    amorsen reported an input
    processing error in the RTP protocol implementation
    (CVE-2009-4055).
    Patrik Karlsson reported an information
    disclosure flaw related to the REGISTER message (CVE-2009-3727).
    A vulnerability was found in the bundled Prototype JavaScript
    library, related to AJAX calls (CVE-2008-7220).
  
Impact :

    A remote attacker could exploit these vulnerabilities by sending a
    specially crafted package, possibly causing a Denial of Service
    condition, or resulting in information disclosure.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201006-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.2.37'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
    available since January 5, 2010. It is likely that your system is
    already no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/asterisk", unaffected:make_list("ge 1.2.37"), vulnerable:make_list("lt 1.2.37"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Asterisk");
}
