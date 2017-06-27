#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14747);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0805");
  script_osvdb_id(9748);
  script_xref(name:"GLSA", value:"200409-20");

  script_name(english:"GLSA-200409-20 : mpg123: Buffer overflow vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200409-20
(mpg123: Buffer overflow vulnerability)

    mpg123 contains a buffer overflow in the code that handles layer2
    decoding of media files.
  
Impact :

    An attacker can possibly exploit this bug with a specially crafted mp3 or mp2 file
    to execute arbitrary code with the permissions of the user running mpg123.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/374433/2004-09-05/2004-09-11/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All mpg123 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=media-sound/mpg123-0.59s-r4'
    # emerge '>=media-sound/mpg123-0.59s-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mpg123");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/06");
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

if (qpkg_check(package:"media-sound/mpg123", unaffected:make_list("ge 0.59s-r4"), vulnerable:make_list("le 0.59s-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mpg123");
}
