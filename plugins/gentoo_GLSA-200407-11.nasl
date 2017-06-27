#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14544);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2004-0645");
  script_osvdb_id(7761);
  script_xref(name:"GLSA", value:"200407-11");

  script_name(english:"GLSA-200407-11 : wv: Buffer overflow vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200407-11
(wv: Buffer overflow vulnerability)

    A use of strcat without proper bounds checking leads to an exploitable
    buffer overflow. The vulnerable code is executed when wv encounters an
    unrecognized token, so a specially crafted file, loaded in wv, can
    trigger the vulnerable code and execute its own arbitrary code. This
    exploit is only possible when the user loads the document into HTML
    view mode.
  
Impact :

    By inducing a user into running wv on a special file, an attacker can
    execute arbitrary code with the permissions of the user running the
    vulnerable program.
  
Workaround :

    Users should not view untrusted documents with wvHtml or applications
    using wv. When loading an untrusted document in an application using
    the wv library, make sure HTML view is disabled."
  );
  # http://www.idefense.com/application/poi/display?id=115&type=vulnerabilities&flashstatus=true
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cf1d63b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest available version.
    # emerge sync
    # emerge -pv '>=app-text/wv-1.0.0-r1'
    # emerge '>=app-text/wv-1.0.0-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/wv", unaffected:make_list("ge 1.0.0-r1"), vulnerable:make_list("lt 1.0.0-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wv");
}
