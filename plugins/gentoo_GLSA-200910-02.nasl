#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200910-02.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(42214);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-1376", "CVE-2009-1889", "CVE-2009-2694", "CVE-2009-3026");
  script_bugtraq_id(35067, 35530, 36071);
  script_xref(name:"GLSA", value:"200910-02");

  script_name(english:"GLSA-200910-02 : Pidgin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200910-02
(Pidgin: Multiple vulnerabilities)

    Multiple vulnerabilities were found in Pidgin:
    Yuriy
    Kaminskiy reported that the OSCAR protocol implementation in Pidgin
    misinterprets the ICQWebMessage message type as the ICQSMS message
    type, triggering an allocation of a large amount of memory
    (CVE-2009-1889).
    Federico Muttis of Core Security Technologies
    reported that the msn_slplink_process_msg() function in
    libpurple/protocols/msn/slplink.c in libpurple as used in Pidgin
    doesn't properly process incoming SLP messages, triggering an overwrite
    of an arbitrary memory location (CVE-2009-2694). NOTE: This issue
    reportedly exists because of an incomplete fix for CVE-2009-1376 (GLSA
    200905-07).
    bugdave reported that protocols/jabber/auth.c in
    libpurple as used in Pidgin does not follow the 'require TSL/SSL'
    preference when connecting to older Jabber servers that do not follow
    the XMPP specification, resulting in a connection to the server without
    the expected encryption (CVE-2009-3026).
  
Impact :

    A remote attacker could send specially crafted SLP (via MSN) or ICQ web
    messages, possibly leading to execution of arbitrary code with the
    privileges of the user running Pidgin, unauthorized information
    disclosure, or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200905-07.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200910-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Pidgin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/pidgin-2.5.9-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(189, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/23");
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

if (qpkg_check(package:"net-im/pidgin", unaffected:make_list("ge 2.5.9-r1"), vulnerable:make_list("lt 2.5.9-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Pidgin");
}
