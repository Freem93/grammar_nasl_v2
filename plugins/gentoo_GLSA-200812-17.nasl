#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200812-17.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35188);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/11/14 14:40:46 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_bugtraq_id(29903, 30036, 30131, 30644, 30802, 31699);
  script_osvdb_id(46550, 46551, 46552, 46553, 46554, 46691, 47469, 47470, 47471, 47472, 47753);
  script_xref(name:"GLSA", value:"200812-17");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"GLSA-200812-17 : Ruby: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200812-17
(Ruby: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in the Ruby interpreter
    and its standard libraries. Drew Yao of Apple Product Security
    discovered the following flaws:
    Arbitrary code execution
    or Denial of Service (memory corruption) in the rb_str_buf_append()
    function (CVE-2008-2662).
    Arbitrary code execution or Denial
    of Service (memory corruption) in the rb_ary_stor() function
    (CVE-2008-2663).
    Memory corruption via alloca in the
    rb_str_format() function (CVE-2008-2664).
    Memory corruption
    ('REALLOC_N') in the rb_ary_splice() and rb_ary_replace() functions
    (CVE-2008-2725).
    Memory corruption ('beg + rlen') in the
    rb_ary_splice() and rb_ary_replace() functions (CVE-2008-2726).
    Furthermore, several other vulnerabilities have been reported:
    Tanaka Akira reported an issue with resolv.rb that enables
    attackers to spoof DNS responses (CVE-2008-1447).
    Akira Tagoh
    of RedHat discovered a Denial of Service (crash) issue in the
    rb_ary_fill() function in array.c (CVE-2008-2376).
    Several
    safe level bypass vulnerabilities were discovered and reported by Keita
    Yamaguchi (CVE-2008-3655).
    Christian Neukirchen is credited
    for discovering a Denial of Service (CPU consumption) attack in the
    WEBRick HTTP server (CVE-2008-3656).
    A fault in the dl module
    allowed the circumvention of taintness checks which could possibly lead
    to insecure code execution was reported by 'sheepman'
    (CVE-2008-3657).
    Tanaka Akira again found a DNS spoofing
    vulnerability caused by the resolv.rb implementation using poor
    randomness (CVE-2008-3905).
    Luka Treiber and Mitja Kolsek
    (ACROS Security) disclosed a Denial of Service (CPU consumption)
    vulnerability in the REXML module when dealing with recursive entity
    expansion (CVE-2008-3790).
  
Impact :

    These vulnerabilities allow remote attackers to execute arbitrary code,
    spoof DNS responses, bypass Ruby's built-in security and taintness
    checks, and cause a Denial of Service via crash or CPU exhaustion.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200812-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ruby users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/ruby-1.8.6_p287-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/ruby", unaffected:make_list("ge 1.8.6_p287-r1"), vulnerable:make_list("lt 1.8.6_p287-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ruby");
}
