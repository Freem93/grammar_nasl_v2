#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200712-18.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(29815);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-5824", "CVE-2007-5825");
  script_bugtraq_id(26310);
  script_osvdb_id(45286);
  script_xref(name:"GLSA", value:"200712-18");

  script_name(english:"GLSA-200712-18 : Multi-Threaded DAAP Daemon: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200712-18
(Multi-Threaded DAAP Daemon: Multiple vulnerabilities)

    nnp discovered multiple vulnerabilities in the XML-RPC handler in the
    file webserver.c. The ws_addarg() function contains a format string
    vulnerability, as it does not properly sanitize username and password
    data from the 'Authorization: Basic' HTTP header line (CVE-2007-5825).
    The ws_decodepassword() and ws_getheaders() functions do not correctly
    handle empty Authorization header lines, or header lines without a ':'
    character, leading to NULL pointer dereferences (CVE-2007-5824).
  
Impact :

    A remote attacker could send specially crafted HTTP requests to the web
    server in the Multi-Threaded DAAP Daemon, possibly leading to the
    execution of arbitrary code with the privileges of the user running the
    web server or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200712-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Multi-Threaded DAAP Daemon users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-sound/mt-daapd-0.2.4.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mt-daapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-sound/mt-daapd", unaffected:make_list("ge 0.2.4.1"), vulnerable:make_list("lt 0.2.4.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Multi-Threaded DAAP Daemon");
}
