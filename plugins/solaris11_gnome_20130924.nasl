#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80625);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2007-4460", "CVE-2013-1788", "CVE-2013-1789", "CVE-2013-1790");

  script_name(english:"Oracle Solaris Third-Party Patch Update : gnome (cve_2007_4460_symlink_attack)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - The RenderV2ToFile function in tag_file.cpp in id3lib
    (aka libid3) 3.8.3 allows local users to overwrite
    arbitrary files via a symlink attack on a temporary file
    whose name is constructed from the name of a file being
    tagged. (CVE-2007-4460)

  - poppler before 0.22.1 allows context-dependent attackers
    to cause a denial of service (crash) and possibly
    execute arbitrary code via vectors that trigger an
    'invalid memory access' in (1) splash/Splash.cc, (2)
    poppler/Function.cc, and (3) poppler/Stream.cc.
    (CVE-2013-1788)

  - splash/Splash.cc in poppler before 0.22.1 allows
    context-dependent attackers to cause a denial of service
    (NULL pointer dereference and crash) via vectors related
    to the (1) Splash::arbitraryTransformMask, (2)
    Splash::blitMask, and (3) Splash::scaleMaskYuXu
    functions. (CVE-2013-1789)

  - poppler/Stream.cc in poppler before 0.22.1 allows
    context-dependent attackers to have an unspecified
    impact via vectors that trigger a read of uninitialized
    memory by the CCITTFaxStream::lookChar function.
    (CVE-2013-1790)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2007_4460_symlink_attack
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67e14e4c"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_poppler
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e71b3f9a"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.10.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:gnome");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^gnome-incorporation$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.10.0.5.0", sru:"SRU 11.1.10.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : gnome\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "gnome");
