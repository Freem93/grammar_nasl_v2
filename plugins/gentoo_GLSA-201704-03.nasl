#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201704-03.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(99276);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/11 16:24:59 $");

  script_cve_id("CVE-2016-5407", "CVE-2016-7942", "CVE-2016-7943", "CVE-2016-7944", "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7949", "CVE-2016-7950", "CVE-2016-7953", "CVE-2017-2624", "CVE-2017-2625", "CVE-2017-2626");
  script_xref(name:"GLSA", value:"201704-03");

  script_name(english:"GLSA-201704-03 : X.Org: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201704-03
(X.Org: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in X.Org server and
      libraries. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    A local or remote users can utilize the vulnerabilities to attach to the
      X.Org session as a user and execute arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201704-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All X.Org-server users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-base/xorg-server-1.19.2'
    All libICE users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/libICE-1.0.9-r1'
    All libXdmcp users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/libXdmcp-1.1.2-r1'
    All libXrender users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/libXrender-0.9.10'
    All libXi users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/libXi-1.7.7'
    All libXrandr users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/libXrandr-1.5.1'
    All libXfixes users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/libXfixes-5.0.3'
    All libXv users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/libXv-1.0.11'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libICE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXdmcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"x11-base/xorg-server", unaffected:make_list("ge 1.19.2"), vulnerable:make_list("lt 1.19.2"))) flag++;
if (qpkg_check(package:"x11-libs/libXrandr", unaffected:make_list("ge 1.5.1"), vulnerable:make_list("lt 1.5.1"))) flag++;
if (qpkg_check(package:"x11-libs/libXi", unaffected:make_list("ge 1.7.7"), vulnerable:make_list("lt 1.7.7"))) flag++;
if (qpkg_check(package:"x11-libs/libXfixes", unaffected:make_list("ge 5.0.3"), vulnerable:make_list("lt 5.0.3"))) flag++;
if (qpkg_check(package:"x11-libs/libXrender", unaffected:make_list("ge 0.9.10"), vulnerable:make_list("lt 0.9.10"))) flag++;
if (qpkg_check(package:"x11-libs/libXv", unaffected:make_list("ge 1.0.11"), vulnerable:make_list("lt 1.0.11"))) flag++;
if (qpkg_check(package:"x11-libs/libICE", unaffected:make_list("ge 1.0.9-r1"), vulnerable:make_list("lt 1.0.9-r1"))) flag++;
if (qpkg_check(package:"x11-libs/libXdmcp", unaffected:make_list("ge 1.1.2-r1"), vulnerable:make_list("lt 1.1.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X.Org");
}
