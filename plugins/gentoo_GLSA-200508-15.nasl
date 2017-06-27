#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200508-15.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19535);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-2728");
  script_osvdb_id(18977);
  script_xref(name:"GLSA", value:"200508-15");

  script_name(english:"GLSA-200508-15 : Apache 2.0: Denial of Service vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200508-15
(Apache 2.0: Denial of Service vulnerability)

    Filip Sneppe discovered that Apache improperly handles byterange
    requests to CGI scripts.
  
Impact :

    A remote attacker may access vulnerable scripts in a malicious way,
    exhausting all RAM and swap space on the server, resulting in a Denial
    of Service of the Apache server.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://issues.apache.org/bugzilla/show_bug.cgi?id=29962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200508-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/apache-2.0.54-r9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/25");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 2.0.54-r9", "lt 2.0"), vulnerable:make_list("lt 2.0.54-r9"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache 2.0");
}
