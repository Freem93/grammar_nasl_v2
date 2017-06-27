#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200503-32.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17632);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0255", "CVE-2005-0399", "CVE-2005-0590", "CVE-2005-0592");
  script_osvdb_id(14185, 14188, 14195, 14937);
  script_xref(name:"GLSA", value:"200503-32");

  script_name(english:"GLSA-200503-32 : Mozilla Thunderbird: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200503-32
(Mozilla Thunderbird: Multiple vulnerabilities)

    The following vulnerabilities were found and fixed in Mozilla
    Thunderbird:
    Mark Dowd from ISS X-Force reported an
    exploitable heap overrun in the GIF processing of obsolete Netscape
    extension 2 (CAN-2005-0399)
    Daniel de Wildt and Gael Delalleau
    discovered a memory overwrite in a string library (CAN-2005-0255)
    Wind Li discovered a possible heap overflow in UTF8 to Unicode
    conversion (CAN-2005-0592)
    Phil Ringnalda reported a possible
    way to spoof Install source with user:pass@host (CAN-2005-0590)
  
Impact :

    The GIF heap overflow could be triggered by a malicious GIF image
    that would end up executing arbitrary code with the rights of the user
    running Thunderbird. The other overflow issues, while not thought to be
    exploitable, would have the same impact. Furthermore, by setting up
    malicious websites and convincing users to follow untrusted links,
    attackers may leverage the spoofing issue to trick user into installing
    malicious extensions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200503-32"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Thunderbird users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-1.0.2'
    All Mozilla Thunderbird binary users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-bin-1.0.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/23");
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

if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 1.0.2"), vulnerable:make_list("lt 1.0.2"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 1.0.2"), vulnerable:make_list("lt 1.0.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Thunderbird");
}
