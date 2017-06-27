#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-24.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14779);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/04/28 18:42:39 $");

  script_cve_id("CVE-2004-0801");
  script_osvdb_id(10000);
  script_xref(name:"GLSA", value:"200409-24");

  script_name(english:"GLSA-200409-24 : Foomatic: Arbitrary command execution in foomatic-rip filter");
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
"The remote host is affected by the vulnerability described in GLSA-200409-24
(Foomatic: Arbitrary command execution in foomatic-rip filter)

    There is a vulnerability in the foomatic-filters package. This
    vulnerability is due to insufficient checking of command-line parameters
    and environment variables in the foomatic-rip filter.
  
Impact :

    This vulnerability may allow both local and remote attackers to execute
    arbitrary commands on the print server with the permissions of the spooler
    (oftentimes the 'lp' user).
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.linuxprinting.org/pipermail/foomatic-devel/2004q3/001996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6443c06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All foomatic users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=net-print/foomatic-3.0.2'
    # emerge '>=net-print/foomatic-3.0.2'
    PLEASE NOTE: You should update foomatic, instead of foomatic-filters. This
    will help to ensure that all other foomatic components remain functional."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:foomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:foomatic-filters");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/14");
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

if (qpkg_check(package:"net-print/foomatic-filters", unaffected:make_list("ge 3.0.2"), vulnerable:make_list("le 3.0.1"))) flag++;
if (qpkg_check(package:"net-print/foomatic", unaffected:make_list("ge 3.0.2"), vulnerable:make_list("le 3.0.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Foomatic");
}
