#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201012-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(51349);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/13 14:19:43 $");

  script_osvdb_id(70102, 70103, 70104, 70105, 70106);
  script_xref(name:"GLSA", value:"201012-01");

  script_name(english:"GLSA-201012-01 : Chromium: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201012-01
(Chromium: Multiple vulnerabilities)

    Multiple vulnerabilities were found in Chromium. For further
    information please consult the release notes referenced below.
  
Impact :

    A remote attacker could trick a user to perform a set of UI actions
    that trigger a possibly exploitable crash, leading to execution of
    arbitrary code or a Denial of Service.
    It was also possible for an attacker to entice a user to visit a
    specially crafted web page that would trigger one of the
    vulnerabilities, leading to execution of arbitrary code within the
    confines of the sandbox, successful Cross-Site Scripting attacks,
    violation of the same-origin policy, successful website spoofing
    attacks, information leak, or a Denial of Service. An attacker could
    also trick a user to perform a set of UI actions that might result in a
    successful website spoofing attack.
    Multiple bugs in the sandbox could result in a sandbox escape.
    Multiple UI bugs could lead to information leak and successful website
    spoofing attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://googlechromereleases.blogspot.com/2010/06/stable-channel-update_24.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce922261"
  );
  # http://googlechromereleases.blogspot.com/2010/07/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aeaddbb2"
  );
  # http://googlechromereleases.blogspot.com/2010/07/stable-channel-update_26.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8918636"
  );
  # http://googlechromereleases.blogspot.com/2010/08/stable-channel-update_19.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82e215b9"
  );
  # http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_14.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08f28453"
  );
  # http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_17.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0db8ffbd"
  );
  # http://googlechromereleases.blogspot.com/2010/10/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?402ad3e1"
  );
  # http://googlechromereleases.blogspot.com/2010/11/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc6b8a66"
  );
  # http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?986a631f"
  );
  # http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates_13.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fb96d8f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201012-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/chromium-8.0.552.224'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 8.0.552.224"), vulnerable:make_list("lt 8.0.552.224"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
