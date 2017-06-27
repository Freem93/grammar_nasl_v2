#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200601-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20414);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-4459");
  script_osvdb_id(22006);
  script_xref(name:"GLSA", value:"200601-04");

  script_name(english:"GLSA-200601-04 : VMware Workstation: Vulnerability in NAT networking");
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
"The remote host is affected by the vulnerability described in GLSA-200601-04
(VMware Workstation: Vulnerability in NAT networking)

    Tim Shelton discovered that vmnet-natd, the host module providing
    NAT-style networking for VMware guest operating systems, is unable to
    process incorrect 'EPRT' and 'PORT' FTP requests.
  
Impact :

    Malicious guest operating systems using the NAT networking feature or
    local VMware Workstation users could exploit this vulnerability to
    execute arbitrary code on the host system with elevated privileges.
  
Workaround :

    Disable the NAT service by following the instructions at http://www.vmware.com/support/k
    b, Answer ID 2002."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/support/kb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/support/kb/enduser/std_adp.php?p_faqid=2000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200601-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VMware Workstation users should upgrade to a fixed version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-emulation/vmware-workstation"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vmware-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulation/vmware-workstation", unaffected:make_list("ge 5.5.1.19175", "rge 4.5.3.19414", "rge 3.2.1.2242-r10"), vulnerable:make_list("lt 5.5.1.19175"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VMware Workstation");
}
