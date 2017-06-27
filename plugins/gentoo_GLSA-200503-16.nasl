#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200503-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17318);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0699", "CVE-2005-0704", "CVE-2005-0705", "CVE-2005-0739", "CVE-2005-0765", "CVE-2005-0766");
  script_osvdb_id(14612, 14665, 14666, 14668, 14669);
  script_xref(name:"GLSA", value:"200503-16");

  script_name(english:"GLSA-200503-16 : Ethereal: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200503-16
(Ethereal: Multiple vulnerabilities)

    There are multiple vulnerabilities in versions of Ethereal earlier than
    0.10.10, including:
    The Etheric, 3GPP2 A11 and IAPP dissectors are vulnerable to buffer
    overflows (CAN-2005-0704, CAN-2005-0699 and CAN-2005-0739).
    The GPRS-LLC could crash when the 'ignore cipher bit' option is
    enabled (CAN-2005-0705).
    Various vulnerabilities in JXTA and sFlow dissectors.
  
Impact :

    An attacker might be able to use these vulnerabilities to crash
    Ethereal and execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround :

    For a temporary workaround you can disable all affected protocol
    dissectors. However, it is strongly recommended that you upgrade to the
    latest stable version."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00018.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200503-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/ethereal-0.10.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/08");
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

if (qpkg_check(package:"net-analyzer/ethereal", unaffected:make_list("ge 0.10.10"), vulnerable:make_list("lt 0.10.10"))) flag++;

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
