#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14662);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0755");
  script_xref(name:"GLSA", value:"200409-08");

  script_name(english:"GLSA-200409-08 : Ruby: CGI::Session creates files insecurely");
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
"The remote host is affected by the vulnerability described in GLSA-200409-08
(Ruby: CGI::Session creates files insecurely)

    The CGI::Session::FileStore implementation (and presumably
    CGI::Session::PStore), which allow data associated with a particular
    Session instance to be written to a file, writes to a file in /tmp with no
    regard for secure permissions. As a result, the file is left with whatever
    the default umask permissions are, which commonly would allow other local
    users to read the data from that session file.
  
Impact :

    Depending on the default umask, any data stored using these methods could
    be read by other users on the system.
  
Workaround :

    By changing the default umask on the system to not permit read access to
    other users (e.g. 0700), one can prevent these files from being readable by
    other users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ruby users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=dev-lang/ruby-your_version'
    # emerge '>=dev-lang/ruby-your_version'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/ruby", unaffected:make_list("rge 1.6.8-r11", "rge 1.8.0-r7", "ge 1.8.2_pre2"), vulnerable:make_list("lt 1.8.2_pre2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ruby: CGI:");
}
