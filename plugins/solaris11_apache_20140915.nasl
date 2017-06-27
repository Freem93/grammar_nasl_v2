#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80588);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-6438", "CVE-2014-0098");

  script_name(english:"Oracle Solaris Third-Party Patch Update : apache (multiple_input_validation_vulnerabilities_in1)");
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

  - The dav_xml_get_cdata function in main/util.c in the
    mod_dav module in the Apache HTTP Server before 2.4.8
    does not properly remove whitespace characters from
    CDATA sections, which allows remote attackers to cause a
    denial of service (daemon crash) via a crafted DAV WRITE
    request. (CVE-2013-6438)

  - The log_cookie function in mod_log_config.c in the
    mod_log_config module in the Apache HTTP Server before
    2.4.8 allows remote attackers to cause a denial of
    service (segmentation fault and daemon crash) via a
    crafted cookie that is not properly handled during
    truncation. (CVE-2014-0098)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_input_validation_vulnerabilities_in1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?262c3bc9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.19.6.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:apache");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
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

if (solaris_check_release(release:"0.5.11-0.175.1.19.0.6.0", sru:"SRU 11.1.19.6.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : apache\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "apache");
