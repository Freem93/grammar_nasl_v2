#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200507-17.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19222);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-0989");
  script_osvdb_id(15682);
  script_xref(name:"GLSA", value:"200507-17");

  script_name(english:"GLSA-200507-17 : Mozilla Thunderbird: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200507-17
(Mozilla Thunderbird: Multiple vulnerabilities)

    The following vulnerabilities were found and fixed in Mozilla
    Thunderbird:
    'moz_bug_r_a4' and 'shutdown' discovered
    that Thunderbird was improperly cloning base objects (MFSA
    2005-56).
    'moz_bug_r_a4' also reported that Thunderbird was
    overly trusting contents, allowing privilege escalation via property
    overrides (MFSA 2005-41, 2005-44), that it failed to validate XHTML DOM
    nodes properly (MFSA 2005-55), and that XBL scripts ran even when
    JavaScript is disabled (MFSA 2005-46).
    'shutdown' discovered a
    possibly exploitable crash in InstallVersion.compareTo (MFSA
    2005-50).
    Andreas Sandblad from Secunia reported that a child
    frame can call top.focus() even if the framing page comes from a
    different origin and has overridden the focus() routine (MFSA
    2005-52).
    Georgi Guninski reported missing Install object
    instance checks in the native implementations of XPInstall-related
    JavaScript objects (MFSA 2005-40).
    Finally, Vladimir V.
    Perepelitsa discovered a memory disclosure bug in JavaScript's regular
    expression string replacement when using an anonymous function as the
    replacement argument (CAN-2005-0989 and MFSA 2005-33).
  
Impact :

    A remote attacker could craft malicious email messages that would
    leverage these issues to inject and execute arbitrary script code with
    elevated privileges or help in stealing information.
  
Workaround :

    There are no known workarounds for all the issues at this time."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#Thunderbird
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92848d5a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200507-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Thunderbird users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-1.0.5'
    All Mozilla Thunderbird binary users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-bin-1.0.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/01");
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

if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 1.0.5"), vulnerable:make_list("lt 1.0.5"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 1.0.5"), vulnerable:make_list("lt 1.0.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Thunderbird");
}
