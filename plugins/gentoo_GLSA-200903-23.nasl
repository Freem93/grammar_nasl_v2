#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200903-23.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35904);
  script_version("$Revision: 1.34 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-3873", "CVE-2008-4401", "CVE-2008-4503", "CVE-2008-4818", "CVE-2008-4819", "CVE-2008-4821", "CVE-2008-4822", "CVE-2008-4823", "CVE-2008-4824", "CVE-2008-5361", "CVE-2008-5362", "CVE-2008-5363", "CVE-2008-5499", "CVE-2009-0114", "CVE-2009-0519", "CVE-2009-0520", "CVE-2009-0521");
  script_bugtraq_id(31117, 31537, 32896, 33880, 33889, 33890);
  script_osvdb_id(48049, 48944, 49753, 49780, 49783, 49785, 49790, 49958, 50073, 50126, 50127, 50796, 51491, 52749, 52917, 53097);
  script_xref(name:"GLSA", value:"200903-23");

  script_name(english:"GLSA-200903-23 : Adobe Flash Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200903-23
(Adobe Flash Player: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Flash Player:
    The access scope of SystemsetClipboard() allows ActionScript
    programs to execute the method without user interaction
    (CVE-2008-3873).
    The access scope of FileReference.browse() and
    FileReference.download() allows ActionScript programs to execute the
    methods without user interaction (CVE-2008-4401).
    The Settings Manager controls can be disguised as normal graphical
    elements. This so-called 'clickjacking' vulnerability was disclosed by
    Robert Hansen of SecTheory, Jeremiah Grossman of WhiteHat Security,
    Eduardo Vela, Matthew Mastracci of DotSpots, and Liu Die Yu of
    TopsecTianRongXin (CVE-2008-4503).
    Adan Barth (UC Berkely) and Collin Jackson (Stanford University)
    discovered a flaw occurring when interpreting HTTP response headers
    (CVE-2008-4818).
    Nathan McFeters and Rob Carter of Ernst and Young's Advanced
    Security Center are credited for finding an unspecified vulnerability
    facilitating DNS rebinding attacks (CVE-2008-4819).
    When used in a Mozilla browser, Adobe Flash Player does not
    properly interpret jar: URLs, according to a report by Gregory
    Fleischer of pseudo-flaw.net (CVE-2008-4821).
    Alex 'kuza55' K. reported that Adobe Flash Player does not properly
    interpret policy files (CVE-2008-4822).
    The vendor credits Stefano Di Paola of Minded Security for
    reporting that an ActionScript attribute is not interpreted properly
    (CVE-2008-4823).
    Riley Hassell and Josh Zelonis of iSEC Partners reported multiple
    input validation errors (CVE-2008-4824).
    The aforementioned researchers also reported that ActionScript 2
    does not verify a member element's size when performing several known
    and other unspecified actions, that DefineConstantPool accepts an
    untrusted input value for a 'constant count' and that character
    elements are not validated when retrieved from a data structure,
    possibly resulting in a NULL pointer dereference (CVE-2008-5361,
    CVE-2008-5362, CVE-2008-5363).
    The vendor reported an unspecified arbitrary code execution
    vulnerability (CVE-2008-5499).
    Liu Die Yu of TopsecTianRongXin reported an unspecified flaw in the
    Settings Manager related to 'clickjacking' (CVE-2009-0114).
    The vendor credits Roee Hay from IBM Rational Application Security
    for reporting an input validation error when processing SWF files
    (CVE-2009-0519).
    Javier Vicente Vallejo reported via the iDefense VCP that Adobe
    Flash does not remove object references properly, leading to a freed
    memory dereference (CVE-2009-0520).
    Josh Bressers of Red Hat and Tavis Ormandy of the Google Security
    Team reported an untrusted search path vulnerability
    (CVE-2009-0521).
  
Impact :

    A remote attacker could entice a user to open a specially crafted SWF
    file, possibly resulting in the execution of arbitrary code with the
    privileges of the user or a Denial of Service (crash). Furthermore a
    remote attacker could gain access to sensitive information, disclose
    memory contents by enticing a user to open a specially crafted PDF file
    inside a Flash application, modify the victim's clipboard or render it
    temporarily unusable, persuade a user into uploading or downloading
    files, bypass security restrictions with the assistance of the user to
    gain access to camera and microphone, conduct Cross-Site Scripting and
    HTTP Header Splitting attacks, bypass the 'non-root domain policy' of
    Flash, and gain escalated privileges.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200903-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-plugins/adobe-flash-10.0.22.87'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ActionScript Launch Command Execution Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 79, 94, 119, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 10.0.22.87"), vulnerable:make_list("lt 10.0.22.87"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Flash Player");
}
