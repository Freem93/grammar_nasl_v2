#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201111-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56686);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2011-2345", "CVE-2011-2346", "CVE-2011-2347", "CVE-2011-2348", "CVE-2011-2349", "CVE-2011-2350", "CVE-2011-2351", "CVE-2011-2834", "CVE-2011-2835", "CVE-2011-2837", "CVE-2011-2838", "CVE-2011-2839", "CVE-2011-2840", "CVE-2011-2841", "CVE-2011-2843", "CVE-2011-2844", "CVE-2011-2845", "CVE-2011-2846", "CVE-2011-2847", "CVE-2011-2848", "CVE-2011-2849", "CVE-2011-2850", "CVE-2011-2851", "CVE-2011-2852", "CVE-2011-2853", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2856", "CVE-2011-2857", "CVE-2011-2858", "CVE-2011-2859", "CVE-2011-2860", "CVE-2011-2861", "CVE-2011-2862", "CVE-2011-2864", "CVE-2011-2874", "CVE-2011-3234", "CVE-2011-3873", "CVE-2011-3875", "CVE-2011-3876", "CVE-2011-3877", "CVE-2011-3878", "CVE-2011-3879", "CVE-2011-3880", "CVE-2011-3881", "CVE-2011-3882", "CVE-2011-3883", "CVE-2011-3884", "CVE-2011-3885", "CVE-2011-3886", "CVE-2011-3887", "CVE-2011-3888", "CVE-2011-3889", "CVE-2011-3890", "CVE-2011-3891");
  script_bugtraq_id(48479, 49279, 49658, 49933, 49938, 50360);
  script_osvdb_id(73504, 73506, 73507, 73508, 73509, 73510, 73511, 74701, 75536, 75538, 75539, 75540, 75541, 75543, 75544, 75545, 75546, 75547, 75548, 75549, 75550, 75551, 75552, 75553, 75555, 75556, 75557, 75558, 75559, 75560, 75561, 75562, 75563, 75564, 75565, 75566, 75567, 76067, 76545, 76546, 76547, 76548, 76549, 76550, 76551, 76552, 76553, 76554, 76555, 76556, 76557, 76558, 76559, 76560, 76561, 76562, 90387, 90388, 90389, 90390, 90446, 90447, 90448, 90449, 90450);
  script_xref(name:"GLSA", value:"201111-01");

  script_name(english:"GLSA-201111-01 : Chromium, V8: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201111-01
(Chromium, V8: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and V8. Please
      review the CVE identifiers and release notes referenced below for
      details.
  
Impact :

    A local attacker could gain root privileges (CVE-2011-1444, fixed in
      chromium-11.0.696.57).
    A context-dependent attacker could entice a user to open a specially
      crafted website or JavaScript program using Chromium or V8, possibly
      resulting in the execution of arbitrary code with the privileges of the
      process, or a Denial of Service condition. The attacker also could obtain
      cookies and other sensitive information, conduct man-in-the-middle
      attacks, perform address bar spoofing, bypass the same origin policy,
      perform Cross-Site Scripting attacks, or bypass pop-up blocks.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://googlechromereleases.blogspot.com/2011/03/chrome-stable-release.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?903021a5"
  );
  # http://googlechromereleases.blogspot.com/2011/03/stable-and-beta-channel-updates.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5960d07"
  );
  # http://googlechromereleases.blogspot.com/2011/04/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68b24c3b"
  );
  # http://googlechromereleases.blogspot.com/2011/04/chrome-stable-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfec542d"
  );
  # http://googlechromereleases.blogspot.com/2011/05/beta-and-stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d77dd99"
  );
  # http://googlechromereleases.blogspot.com/2011/05/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b79e4c8b"
  );
  # http://googlechromereleases.blogspot.com/2011/05/stable-channel-update_24.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff69daca"
  );
  # http://googlechromereleases.blogspot.com/2011/06/stable-channel-update_28.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0153f07f"
  );
  # http://googlechromereleases.blogspot.com/2011/06/chrome-stable-release.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27ba5b5d"
  );
  # http://googlechromereleases.blogspot.com/2011/08/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?739f0064"
  );
  # http://googlechromereleases.blogspot.com/2011/08/stable-channel-update_22.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ab50493"
  );
  # http://googlechromereleases.blogspot.com/2011/09/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?221de82d"
  );
  # http://googlechromereleases.blogspot.com/2011/09/stable-channel-update_16.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ce99226"
  );
  # http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f63d24f5"
  );
  # http://googlechromereleases.blogspot.com/2011/10/chrome-stable-release.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?614d8eb8"
  );
  # http://googlechromereleases.blogspot.com/2011/01/chrome-stable-release.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b44c4173"
  );
  # http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_28.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ac088da"
  );
  # http://googlechromereleases.blogspot.com/2011/02/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f585e13"
  );
  # http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_08.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba155401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201111-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-15.0.874.102'
    All V8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/v8-3.5.10.22'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/02");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 15.0.874.102"), vulnerable:make_list("lt 15.0.874.102"))) flag++;
if (qpkg_check(package:"dev-lang/v8", unaffected:make_list("ge 3.5.10.22"), vulnerable:make_list("lt 3.5.10.22"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / V8");
}
