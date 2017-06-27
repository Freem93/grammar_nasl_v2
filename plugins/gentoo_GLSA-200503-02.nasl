#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200503-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17249);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0258", "CVE-2005-0259");
  script_bugtraq_id(12618, 12621, 12623, 12678);
  script_osvdb_id(14040, 14041);
  script_xref(name:"GLSA", value:"200503-02");

  script_name(english:"GLSA-200503-02 : phpBB: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200503-02
(phpBB: Multiple vulnerabilities)

    It was discovered that phpBB contains a flaw in the session
    handling code and a path disclosure bug. AnthraX101 discovered that
    phpBB allows local users to read arbitrary files, if the 'Enable remote
    avatars' and 'Enable avatar uploading' options are set (CAN-2005-0259).
    He also found out that incorrect input validation in
    'usercp_avatar.php' and 'usercp_register.php' makes phpBB vulnerable to
    directory traversal attacks, if the 'Gallery avatars' setting is
    enabled (CAN-2005-0258).
  
Impact :

    Remote attackers can exploit the session handling flaw to gain
    phpBB administrator rights. By providing a local and a remote location
    for an avatar and setting the 'Upload Avatar from a URL:' field to
    point to the target file, a malicious local user can read arbitrary
    local files. By inserting '/../' sequences into the 'avatarselect'
    parameter, a remote attacker can exploit the directory traversal
    vulnerability to delete arbitrary files. A flaw in the 'viewtopic.php'
    script can be exploited to expose the full path of PHP scripts.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=267563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200503-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpBB users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/phpBB-2.0.13'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpBB");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/21");
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

if (qpkg_check(package:"www-apps/phpBB", unaffected:make_list("ge 2.0.13"), vulnerable:make_list("lt 2.0.13"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpBB");
}
