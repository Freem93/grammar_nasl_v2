#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200702-07.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24368);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2007-0243");
  script_bugtraq_id(22085);
  script_osvdb_id(32834);
  script_xref(name:"GLSA", value:"200702-07");

  script_name(english:"GLSA-200702-07 : Sun JDK/JRE: Execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200702-07
(Sun JDK/JRE: Execution of arbitrary code)

    A anonymous researcher discovered that an error in the handling of a
    GIF image with a zero width field block leads to a memory corruption
    flaw.
  
Impact :

    An attacker could entice a user to run a specially crafted Java applet
    or application that would load a crafted GIF image, which could result
    in escalation of privileges and unauthorized access to system
    resources.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200702-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sun Java Development Kit 1.5 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.5.0.10'
    All Sun Java Development Kit 1.4 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '=dev-java/sun-jdk-1.4.2*'
    All Sun Java Runtime Environment 1.5 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.5.0.10'
    All Sun Java Runtime Environment 1.4 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '=dev-java/sun-jre-bin-1.4.2*'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/16");
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

if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list("ge 1.5.0.10", "rge 1.4.2.18", "rge 1.4.2.17", "rge 1.4.2.15", "rge 1.4.2.14", "rge 1.4.2.13"), vulnerable:make_list("lt 1.5.0.10", "lt 1.4.2.13"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list("ge 1.5.0.10", "rge 1.4.2.18", "rge 1.4.2.17", "rge 1.4.2.15", "rge 1.4.2.14", "rge 1.4.2.13"), vulnerable:make_list("lt 1.5.0.10", "lt 1.4.2.13"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sun JDK/JRE");
}
