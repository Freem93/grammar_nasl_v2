#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200806-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33189);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");
  script_osvdb_id(44943, 44944, 44945);
  script_xref(name:"GLSA", value:"200806-04");

  script_name(english:"GLSA-200806-04 : rdesktop: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200806-04
(rdesktop: Multiple vulnerabilities)

    An anonymous researcher reported multiple vulnerabilities in rdesktop
    via iDefense Labs:
    An integer underflow error exists in
    the function iso_recv_msg() in the file iso.c which can be triggered
    via a specially crafted RDP request, causing a heap-based buffer
    overflow (CVE-2008-1801).
    An input validation error exists in
    the function process_redirect_pdu() in the file rdp.c which can be
    triggered via a specially crafted RDP redirect request, causing a
    BSS-based buffer overflow (CVE-2008-1802).
    An integer signedness error exists in the function xrealloc() in the
    file rdesktop.c which can be be exploited to cause a heap-based buffer
    overflow (CVE-2008-1803).
  
Impact :

    An attacker could exploit these vulnerabilities by enticing a user to
    connect to a malicious RDP server thereby allowing the attacker to
    execute arbitrary code or cause a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200806-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All rdesktop users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/rdesktop-1.6.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rdesktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/rdesktop", unaffected:make_list("ge 1.6.0"), vulnerable:make_list("lt 1.6.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rdesktop");
}
