#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201701-22.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(96416);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/12 14:54:53 $");

  script_cve_id("CVE-2016-1247");
  script_xref(name:"GLSA", value:"201701-22");

  script_name(english:"GLSA-201701-22 : NGINX: Privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-201701-22
(NGINX: Privilege escalation)

    It was discovered that Gentoo&rsquo;s default NGINX installation applied
      similar problematic permissions on &ldquo;/var/log/nginx&rdquo; as Debian
      (DSA-3701) and is therefore vulnerable to the same attack described in
      CVE-2016-1247.
  
Impact :

    A local attacker, who either is already NGINX&rsquo;s system user or belongs
      to NGINX&rsquo;s group, could potentially escalate privileges.
  
Workaround :

    Ensure that no untrusted user can create files in directories which are
      used by NGINX (or an NGINX vhost) to store log files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3701"
  );
  # https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1440e63"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201701-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All NGINX users should upgrade to the latest ebuild revision:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/nginx-1.10.2-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");
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

if (qpkg_check(package:"www-servers/nginx", unaffected:make_list("ge 1.10.2-r3"), vulnerable:make_list("lt 1.10.2-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NGINX");
}
