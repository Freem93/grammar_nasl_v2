#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-36.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59709);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2011-1098", "CVE-2011-1154", "CVE-2011-1155", "CVE-2011-1549");
  script_bugtraq_id(47103, 47107, 47108, 47170);
  script_osvdb_id(73707, 73708, 73709, 74754, 75258);
  script_xref(name:"GLSA", value:"201206-36");

  script_name(english:"GLSA-201206-36 : logrotate: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-36
(logrotate: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in logrotate. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A local attacker could use this flaw to truncate arbitrary system file,
      to change file owner or mode on arbitrary system files, to conduct
      symlink attacks and send arbitrary system files, to execute arbitrary
      system commands, to cause abort in subsequent logrotate runs, to disclose
      sensitive information, to execute arbitrary code or cause a Denial of
      Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-36"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All logrotate users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-admin/logrotate-3.8.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:logrotate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-admin/logrotate", unaffected:make_list("ge 3.8.0"), vulnerable:make_list("lt 3.8.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "logrotate");
}
