#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80584);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2012-3499", "CVE-2012-4558");

  script_name(english:"Oracle Solaris Third-Party Patch Update : apache (multiple_cross_site_scripting_vulnerabilities)");
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

  - Multiple cross-site scripting (XSS) vulnerabilities in
    the Apache HTTP Server 2.2.x before 2.2.24-dev and 2.4.x
    before 2.4.4 allow remote attackers to inject arbitrary
    web script or HTML via vectors involving hostnames and
    URIs in the (1) mod_imagemap, (2) mod_info, (3)
    mod_ldap, (4) mod_proxy_ftp, and (5) mod_status modules.
    (CVE-2012-3499)

  - Multiple cross-site scripting (XSS) vulnerabilities in
    the balancer_handler function in the manager interface
    in mod_proxy_balancer.c in the mod_proxy_balancer module
    in the Apache HTTP Server 2.2.x before 2.2.24-dev and
    2.4.x before 2.4.4 allow remote attackers to inject
    arbitrary web script or HTML via a crafted string.
    (CVE-2012-4558)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_cross_site_scripting_vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b91c3d1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.7.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:apache");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^apache-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.7.0.5.0", sru:"SRU 11.1.7.5.0") > 0) flag++;

if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  error_extra = 'Affected package : apache\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "apache");
