#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200906-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39571);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/19 14:14:42 $");

  script_cve_id("CVE-2008-5519");
  script_osvdb_id(53381);
  script_xref(name:"GLSA", value:"200906-04");

  script_name(english:"GLSA-200906-04 : Apache Tomcat JK Connector: Information disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-200906-04
(Apache Tomcat JK Connector: Information disclosure)

    The Red Hat Security Response Team discovered that mod_jk does not
    properly handle (1) requests setting the 'Content-Length' header while
    not providing data and (2) clients sending repeated requests very
    quickly.
  
Impact :

    A remote attacker could send specially crafted requests or a large
    number of requests at a time, possibly resulting in the disclosure of a
    response intended for another client.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200906-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache Tomcat JK Connector users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apache/mod_jk-1.2.27'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_jk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/30");
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

if (qpkg_check(package:"www-apache/mod_jk", unaffected:make_list("ge 1.2.27"), vulnerable:make_list("lt 1.2.27"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache Tomcat JK Connector");
}
