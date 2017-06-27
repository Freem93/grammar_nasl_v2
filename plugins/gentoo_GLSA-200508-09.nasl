#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200508-09.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19442);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-2547");
  script_osvdb_id(18770);
  script_xref(name:"GLSA", value:"200508-09");

  script_name(english:"GLSA-200508-09 : bluez-utils: Bluetooth device name validation vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200508-09
(bluez-utils: Bluetooth device name validation vulnerability)

    The name of a Bluetooth device is improperly validated by the hcid
    utility when a remote device attempts to pair itself with a computer.
  
Impact :

    An attacker could create a malicious device name on a Bluetooth
    device resulting in arbitrary commands being executed as root upon
    attempting to pair the device with the computer.
  
Workaround :

    There are no known workarounds at this time."
  );
  # http://cvs.sourceforge.net/viewcvs.py/bluez/utils/ChangeLog?rev=1.28&view=markup
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e655d653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200508-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All bluez-utils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-wireless/bluez-utils-2.19'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bluez-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/04");
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

if (qpkg_check(package:"net-wireless/bluez-utils", unaffected:make_list("ge 2.19"), vulnerable:make_list("lt 2.19"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez-utils");
}
