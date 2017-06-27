#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200904-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(38161);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0164", "CVE-2009-0166");
  script_bugtraq_id(34568, 34571);
  script_osvdb_id(54461, 54462, 54465, 54466, 54467, 54468, 54469, 54470, 54471, 54472, 54473, 54476, 54477, 54478, 54479, 54480, 54481, 54482, 54483, 54484, 54485, 54486, 54487, 54488, 54489, 54490, 54491, 54495, 54496);
  script_xref(name:"GLSA", value:"200904-20");

  script_name(english:"GLSA-200904-20 : CUPS: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200904-20
(CUPS: Multiple vulnerabilities)

    The following issues were reported in CUPS:
    iDefense
    reported an integer overflow in the _cupsImageReadTIFF() function in
    the 'imagetops' filter, leading to a heap-based buffer overflow
    (CVE-2009-0163).
    Aaron Siegel of Apple Product Security
    reported that the CUPS web interface does not verify the content of the
    'Host' HTTP header properly (CVE-2009-0164).
    Braden Thomas and
    Drew Yao of Apple Product Security reported that CUPS is vulnerable to
    CVE-2009-0146, CVE-2009-0147 and CVE-2009-0166, found earlier in xpdf
    and poppler.
  
Impact :

    A remote attacker might send or entice a user to send a specially
    crafted print job to CUPS, possibly resulting in the execution of
    arbitrary code with the privileges of the configured CUPS user -- by
    default this is 'lp', or a Denial of Service. Furthermore, the web
    interface could be used to conduct DNS rebinding attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200904-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-print/cups-1.3.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/27");
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

if (qpkg_check(package:"net-print/cups", unaffected:make_list("ge 1.3.10"), vulnerable:make_list("lt 1.3.10"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CUPS");
}
