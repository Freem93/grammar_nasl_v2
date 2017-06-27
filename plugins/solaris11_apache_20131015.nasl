#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80585);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2012-3499", "CVE-2013-1862", "CVE-2013-1896");

  script_name(english:"Oracle Solaris Third-Party Patch Update : apache (cve_2013_1896_denial_of)");
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

  - mod_rewrite.c in the mod_rewrite module in the Apache
    HTTP Server 2.2.x before 2.2.25 writes data to a log
    file without sanitizing non-printable characters, which
    might allow remote attackers to execute arbitrary
    commands via an HTTP request containing an escape
    sequence for a terminal emulator. (CVE-2013-1862)

  - mod_dav.c in the Apache HTTP Server before 2.2.25 does
    not properly determine whether DAV is enabled for a URI,
    which allows remote attackers to cause a denial of
    service (segmentation fault) via a MERGE request in
    which the URI is configured for handling by the
    mod_dav_svn module, but a certain href attribute in XML
    data refers to a non-DAV URI. (CVE-2013-1896)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2013_1896_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_apache_http4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?411a1e47"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.11.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:apache");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
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

if (solaris_check_release(release:"0.5.11-0.175.1.11.0.4.0", sru:"SRU 11.1.11.4.0") > 0) flag++;

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
