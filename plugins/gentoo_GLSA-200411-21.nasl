#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-21.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15696);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-0882", "CVE-2004-0930");
  script_osvdb_id(11555);
  script_xref(name:"GLSA", value:"200411-21");

  script_name(english:"GLSA-200411-21 : Samba: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200411-21
(Samba: Multiple vulnerabilities)

    Samba fails to do proper bounds checking when handling
    TRANSACT2_QFILEPATHINFO replies. Additionally an input validation flaw
    exists in ms_fnmatch.c when matching filenames that contain wildcards.
  
Impact :

    An attacker may be able to execute arbitrary code with the permissions
    of the user running Samba. A remote attacker may also be able to cause
    an abnormal consumption of CPU resources, resulting in slower
    performance of the server or even a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.samba.org/samba/security/CAN-2004-0930.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2004-0930.html"
  );
  # http://security.e-matters.de/advisories/132004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/381124/2004-11-15/2004-11-21/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-fs/samba-3.0.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-fs/samba", unaffected:make_list("ge 3.0.8", "lt 3.0"), vulnerable:make_list("lt 3.0.8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Samba");
}
