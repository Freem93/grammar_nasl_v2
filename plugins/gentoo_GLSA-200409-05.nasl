#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14652);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-1466");
  script_osvdb_id(9019);
  script_xref(name:"GLSA", value:"200409-05");

  script_name(english:"GLSA-200409-05 : Gallery: Arbitrary command execution");
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
"The remote host is affected by the vulnerability described in GLSA-200409-05
(Gallery: Arbitrary command execution)

    The upload handling code in Gallery places uploaded files in a
    temporary directory. After 30 seconds, these files are deleted if they
    are not valid images. However, since the file exists for 30 seconds, a
    carefully crafted script could be initiated by the remote attacker
    during this 30 second timeout. Note that the temporary directory has to
    be located inside the webroot and an attacker needs to have upload
    rights either as an authenticated user or via 'EVERYBODY'.
  
Impact :

    An attacker could run arbitrary code as the user running PHP.
  
Workaround :

    There are several workarounds to this vulnerability:
    Make sure that your temporary directory is not contained in the
    webroot; by default it is located outside the webroot.
    Disable upload rights to all albums for 'EVERYBODY'; upload is
    disabled by default.
    Disable debug and dev mode; these settings are disabled by
    default.
    Disable allow_url_fopen in php.ini."
  );
  # http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0757.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6666e756"
  );
  # http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=134&mode=thread&order=0&thold=0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?864e87f5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Gallery users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=www-apps/gallery-1.4.4_p2'
    # emerge '>=www-apps/gallery-1.4.4_p2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gallery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/19");
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

if (qpkg_check(package:"www-apps/gallery", unaffected:make_list("ge 1.4.4_p2"), vulnerable:make_list("lt 1.4.4_p2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Gallery");
}
