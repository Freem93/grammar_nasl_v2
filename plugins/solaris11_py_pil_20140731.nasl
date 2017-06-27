#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80746);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2014-1932", "CVE-2014-1933");

  script_name(english:"Oracle Solaris Third-Party Patch Update : py_pil (multiple_vulnerabilities_in_python_image)");
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

  - The (1) load_djpeg function in JpegImagePlugin.py, (2)
    Ghostscript function in EpsImagePlugin.py, (3) load
    function in IptcImagePlugin.py, and (4) _copy function
    in Image.py in Python Image Library (PIL) 1.1.7 and
    earlier and Pillow before 2.3.1 do not properly create
    temporary files, which allow local users to overwrite
    arbitrary files and obtain sensitive information via a
    symlink attack on the temporary file. (CVE-2014-1932)

  - The (1) JpegImagePlugin.py and (2) EpsImagePlugin.py
    scripts in Python Image Library (PIL) 1.1.7 and earlier
    and Pillow before 2.3.1 uses the names of temporary
    files on the command line, which makes it easier for
    local users to conduct symlink attacks by listing the
    processes. (CVE-2014-1933)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_python_image
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b54342ac"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:py_pil");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^py_pil$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "py_pil");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.0.0.0.0", sru:"11.2 SRU 0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : py_pil\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "py_pil");
