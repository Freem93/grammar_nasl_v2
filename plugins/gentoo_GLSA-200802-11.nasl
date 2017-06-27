#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200802-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31294);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2007-3762", "CVE-2007-3763", "CVE-2007-3764", "CVE-2007-4103");
  script_osvdb_id(38194, 38195, 38196, 38197);
  script_xref(name:"GLSA", value:"200802-11");

  script_name(english:"GLSA-200802-11 : Asterisk: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200802-11
(Asterisk: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in Asterisk:
    Russel Bryant reported a stack-based buffer overflow in the IAX2 channel
    driver (chan_iax2) when bridging calls between chan_iax2 and any
    channel driver that uses RTP for media (CVE-2007-3762).
    Chris
    Clark and Zane Lackey (iSEC Partners) reported a NULL pointer
    dereference in the IAX2 channel driver (chan_iax2)
    (CVE-2007-3763).
    Will Drewry (Google Security) reported a
    vulnerability in the Skinny channel driver (chan_skinny), resulting in
    an overly large memcpy (CVE-2007-3764).
    Will Drewry (Google
    Security) reported a vulnerability in the IAX2 channel driver
    (chan_iax2), that does not correctly handle unauthenticated
    transactions using a 3-way handshake (CVE-2007-4103).
  
Impact :

    By sending a long voice or video RTP frame, a remote attacker could
    possibly execute arbitrary code on the target machine. Sending
    specially crafted LAGRQ or LAGRP frames containing information elements
    of IAX frames, or a certain data length value in a crafted packet, or
    performing a flood of calls not completing a 3-way handshake, could
    result in a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200802-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.2.17-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/asterisk", unaffected:make_list("rge 1.2.17-r1", "ge 1.2.21.1-r1"), vulnerable:make_list("lt 1.2.21.1-r1"))) flag++;

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
