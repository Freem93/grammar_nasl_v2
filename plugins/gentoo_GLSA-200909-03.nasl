#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200909-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(40911);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_osvdb_id(56765, 56766);
  script_xref(name:"GLSA", value:"200909-03");

  script_name(english:"GLSA-200909-03 : Apache Portable Runtime, APR Utility Library: Execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200909-03
(Apache Portable Runtime, APR Utility Library: Execution of arbitrary code)

    Matt Lewis reported multiple Integer overflows in the apr_rmm_malloc(),
    apr_rmm_calloc(), and apr_rmm_realloc() functions in misc/apr_rmm.c of
    APR-Util and in memory/unix/apr_pools.c of APR, both occurring when
    aligning memory blocks.
  
Impact :

    A remote attacker could entice a user to connect to a malicious server
    with software that uses the APR or act as a malicious client to a
    server that uses the APR (such as Subversion or Apache servers),
    possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200909-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache Portable Runtime users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/apr-1.3.8'
    All APR Utility Library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/apr-util-1.3.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/10");
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

if (qpkg_check(package:"dev-libs/apr-util", unaffected:make_list("ge 1.3.9"), vulnerable:make_list("lt 1.3.9"))) flag++;
if (qpkg_check(package:"dev-libs/apr", unaffected:make_list("ge 1.3.8"), vulnerable:make_list("lt 1.3.8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache Portable Runtime / APR Utility Library");
}
