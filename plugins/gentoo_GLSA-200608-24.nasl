#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200608-24.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22286);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:51 $");

  script_cve_id("CVE-2006-4089");
  script_osvdb_id(27883, 27884, 27885);
  script_xref(name:"GLSA", value:"200608-24");

  script_name(english:"GLSA-200608-24 : AlsaPlayer: Multiple buffer overflows");
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
"The remote host is affected by the vulnerability described in GLSA-200608-24
(AlsaPlayer: Multiple buffer overflows)

    AlsaPlayer contains three buffer overflows: in the function that
    handles the HTTP connections, the GTK interface, and the CDDB querying
    mechanism.
  
Impact :

    An attacker could exploit the first vulnerability by enticing a user to
    load a malicious URL resulting in the execution of arbitrary code with
    the permissions of the user running AlsaPlayer.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200608-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"AlsaPlayer has been masked in Portage pending the resolution of these
    issues. AlsaPlayer users are advised to uninstall the package until
    further notice:
    # emerge --ask --unmerge 'media-sound/alsaplayer'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:alsaplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-sound/alsaplayer", unaffected:make_list(), vulnerable:make_list("le 0.99.76-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "AlsaPlayer");
}
