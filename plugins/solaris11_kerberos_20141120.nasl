#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80655);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/28 21:57:29 $");

  script_cve_id("CVE-2014-4345");

  script_name(english:"Oracle Solaris Third-Party Patch Update : kerberos (cve_2014_4345_numeric_errors)");
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

  - Off-by-one error in the krb5_encode_krbsecretkey
    function in plugins/kdb/ldap/
    libkdb_ldap/ldap_principal2.c in the LDAP KDB module in
    kadmind in MIT Kerberos 5 (aka krb5) 1.6.x through
    1.11.x before 1.11.6 and 1.12.x before 1.12.2 allows
    remote authenticated users to cause a denial of service
    (buffer overflow) or possibly execute arbitrary code via
    a series of 'cpw -keepold' commands. (CVE-2014-4345)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_4345_numeric_errors
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b55a25b5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.4.6.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:kerberos");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/20");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^kerberos-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "kerberos");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.4.0.6.0", sru:"SRU 11.2.4.6.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : kerberos\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "kerberos");
