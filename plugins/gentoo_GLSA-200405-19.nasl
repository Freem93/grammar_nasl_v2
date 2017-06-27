#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-19.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14505);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0473");
  script_xref(name:"GLSA", value:"200405-19");

  script_name(english:"GLSA-200405-19 : Opera telnet URI handler file creation/truncation vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200405-19
(Opera telnet URI handler file creation/truncation vulnerability)

    The telnet URI handler in Opera does not check for leading '-'
    characters in the host name. Consequently, a maliciously-crafted
    telnet:// link may be able to pass options to the telnet program
    itself. One example would be the following:
    telnet://-nMyFile
    If MyFile exists in the user's home directory and the user clicking on
    the link has write permissions to it, the contents of the file will be
    overwritten with the output of the telnet trace information. If MyFile
    does not exist, the file will be created in the user's home directory.
  
Impact :

    This exploit has two possible impacts. First, it may create new files
    in the user's home directory. Second, and far more serious, it may
    overwrite existing files that the user has write permissions to. An
    attacker with some knowledge of a user's home directory might be able
    to destroy important files stored within.
  
Workaround :

    Disable the telnet URI handler from within Opera."
  );
  # http://www.idefense.com/application/poi/display?id=104&type=vulnerabilities&flashstatus=true
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aacb7758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users are encouraged to upgrade to the latest version of the
    program:
    # emerge sync
    # emerge -pv '>=www-client/opera-7.50_beta1'
    # emerge '>=www-client/opera-7.50_beta1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 7.50_beta1"), vulnerable:make_list("lt 7.50_beta1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "www-client/opera");
}
