#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200512-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20315);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3651");
  script_bugtraq_id(15794);
  script_osvdb_id(21599);
  script_xref(name:"GLSA", value:"200512-06");

  script_name(english:"GLSA-200512-06 : Ethereal: Buffer overflow in OSPF protocol dissector");
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
"The remote host is affected by the vulnerability described in GLSA-200512-06
(Ethereal: Buffer overflow in OSPF protocol dissector)

    iDEFENSE reported a possible overflow due to the lack of bounds
    checking in the dissect_ospf_v3_address_prefix() function, part of the
    OSPF protocol dissector.
  
Impact :

    An attacker might be able to craft a malicious network flow that
    would crash Ethereal. It may be possible, though unlikely, to exploit
    this flaw to execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.idefense.com/application/poi/display?id=349&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66833b5e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200512-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/ethereal-0.10.13-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/09");
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

if (qpkg_check(package:"net-analyzer/ethereal", unaffected:make_list("ge 0.10.13-r2"), vulnerable:make_list("lt 0.10.13-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ethereal");
}
