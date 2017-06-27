#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200806-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33265);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/04/28 18:42:39 $");

  script_osvdb_id(35483, 36199, 36200, 37756, 37759, 37760, 37761, 37762, 37763, 37765, 40834, 40931, 41146, 41147, 42589, 42590, 42591, 42592, 42593, 42594, 42595, 42596, 42597, 42598, 42599, 42600, 42601, 42602, 45527);
  script_xref(name:"GLSA", value:"200806-11");

  script_name(english:"GLSA-200806-11 : IBM JDK/JRE: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200806-11
(IBM JDK/JRE: Multiple vulnerabilities)

    Because of sharing the same codebase, IBM JDK and JRE are affected by
    the vulnerabilities mentioned in GLSA 200804-20.
  
Impact :

    A remote attacker could entice a user to run a specially crafted applet
    on a website or start an application in Java Web Start to execute
    arbitrary code outside of the Java sandbox and of the Java security
    restrictions with the privileges of the user running Java. The attacker
    could also obtain sensitive information, create, modify, rename and
    read local files, execute local applications, establish connections in
    the local network, bypass the same origin policy, and cause a Denial of
    Service via multiple vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200804-20.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200806-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All IBM JDK 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jdk-bin-1.5.0.7'
    All IBM JDK 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jdk-bin-1.4.2.11'
    All IBM JRE 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jre-bin-1.5.0.7'
    All IBM JRE 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jre-bin-1.4.2.11'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ibm-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ibm-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
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

if (qpkg_check(package:"dev-java/ibm-jre-bin", unaffected:make_list("ge 1.5.0.7", "rge 1.4.2.11"), vulnerable:make_list("lt 1.5.0.7"))) flag++;
if (qpkg_check(package:"dev-java/ibm-jdk-bin", unaffected:make_list("ge 1.5.0.7", "rge 1.4.2.11"), vulnerable:make_list("lt 1.5.0.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IBM JDK/JRE");
}
