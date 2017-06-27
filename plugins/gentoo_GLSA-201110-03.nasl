#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56445);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2010-2761", "CVE-2010-3172", "CVE-2010-3764", "CVE-2010-4411", "CVE-2010-4567", "CVE-2010-4568", "CVE-2010-4569", "CVE-2010-4570", "CVE-2010-4572", "CVE-2011-0046", "CVE-2011-0048", "CVE-2011-2379", "CVE-2011-2380", "CVE-2011-2381", "CVE-2011-2976", "CVE-2011-2977", "CVE-2011-2978", "CVE-2011-2979");
  script_bugtraq_id(44618, 45145, 45982, 49042);
  script_osvdb_id(69221, 69222, 69588, 70699, 70700, 70701, 70702, 70703, 70704, 70705, 70706, 70707, 70708, 70709, 70710, 74297, 74298, 74299, 74300, 74301, 74302, 74303);
  script_xref(name:"GLSA", value:"201110-03");

  script_name(english:"GLSA-201110-03 : Bugzilla: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-03
(Bugzilla: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Bugzilla. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could conduct cross-site scripting attacks, conduct
      script insertion and spoofing attacks, hijack the authentication of
      arbitrary users, inject arbitrary HTTP headers, obtain access to
      arbitrary accounts, disclose the existence of confidential groups and its
      names, or inject arbitrary e-mail headers.
    A local attacker could disclose the contents of temporarfy files for
      uploaded attachments.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Bugzilla users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/bugzilla-3.6.6'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since August 27, 2011. It is likely that your system is already
      no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/bugzilla", unaffected:make_list("ge 3.6.6"), vulnerable:make_list("lt 3.6.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Bugzilla");
}
