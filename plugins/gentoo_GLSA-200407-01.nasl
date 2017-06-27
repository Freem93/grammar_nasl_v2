#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14534);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0655");
  script_osvdb_id(7358);
  script_xref(name:"GLSA", value:"200407-01");

  script_name(english:"GLSA-200407-01 : Esearch: Insecure temp file handling");
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
"The remote host is affected by the vulnerability described in GLSA-200407-01
(Esearch: Insecure temp file handling)

    The eupdatedb utility uses a temporary file (/tmp/esearchdb.py.tmp) to
    indicate that the eupdatedb process is running. When run, eupdatedb
    checks to see if this file exists, but it does not check to see if it
    is a broken symlink. In the event that the file is a broken symlink,
    the script will create the file pointed to by the symlink, instead of
    printing an error and exiting.
  
Impact :

    An attacker could create a symlink from /tmp/esearchdb.py.tmp to a
    nonexistent file (such as /etc/nologin), and the file will be created
    the next time esearchdb is run.
  
Workaround :

    There is no known workaround at this time. All users should upgrade to
    the latest available version of esearch."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest available version of esearch, as
    follows:
    # emerge sync
    # emerge -pv '>=app-portage/esearch-0.6.2'
    # emerge '>=app-portage/esearch-0.6.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:esearch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/01");
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

if (qpkg_check(package:"app-portage/esearch", unaffected:make_list("ge 0.6.2"), vulnerable:make_list("le 0.6.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Esearch");
}
