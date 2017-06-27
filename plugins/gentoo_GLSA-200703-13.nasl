#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200703-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24830);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:53 $");

  script_cve_id("CVE-2006-0705");
  script_osvdb_id(23120, 23172);
  script_xref(name:"GLSA", value:"200703-13");

  script_name(english:"GLSA-200703-13 : SSH Communications Security's Secure Shell Server: SFTP privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200703-13
(SSH Communications Security's Secure Shell Server: SFTP privilege escalation)

    The SSH Secure Shell Server contains a format string vulnerability in
    the SFTP code that handles file transfers (scp2 and sftp2). In some
    situations, this code passes the accessed filename to the system log.
    During this operation, an unspecified error could allow uncontrolled
    stack access.
  
Impact :

    An authenticated system user may be able to exploit this vulnerability
    to bypass command restrictions, or run commands as another user.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200703-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This package is currently masked, there is no upgrade path for the
    3.2.x version, and a license must be purchased in order to update to a
    non-vulnerable version. Because of this, we recommend unmerging this
    package:
    # emerge --ask --verbose --unmerge net-misc/ssh"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/ssh", unaffected:make_list(), vulnerable:make_list("lt 4.3.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SSH Communications Security's Secure Shell Server");
}
