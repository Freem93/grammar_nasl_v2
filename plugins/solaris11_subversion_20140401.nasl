#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80777);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-1849", "CVE-2013-4505");

  script_name(english:"Oracle Solaris Third-Party Patch Update : subversion (cve_2009_0179_denial_of1)");
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

  - The mod_dav_svn Apache HTTPD server module in Subversion
    1.6.x through 1.6.20 and 1.7.0 through 1.7.8 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and crash) via a PROPFIND request
    for an activity URL. (CVE-2013-1849)

  - The is_this_legal function in mod_dontdothat for Apache
    Subversion 1.4.0 through 1.7.13 and 1.8.0 through 1.8.4
    allows remote attackers to bypass intended access
    restrictions and possibly cause a denial of service
    (resource consumption) via a relative URL in a REPORT
    request. (CVE-2013-4505)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2009_0179_denial_of1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2013_4505_permissions_privileges
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bd7c7f4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.17.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:subversion");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/01");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^subversion$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.17.0.5.0", sru:"SRU 11.1.17.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : subversion\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "subversion");
