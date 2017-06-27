#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80650);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-1528", "CVE-2011-1529", "CVE-2011-4151");

  script_name(english:"Oracle Solaris Third-Party Patch Update : kerberos (multiple_input_validation_vulnerabilities_in)");
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

  - The krb5_ldap_lockout_audit function in the Key
    Distribution Center (KDC) in MIT Kerberos 5 (aka krb5)
    1.8 through 1.8.4 and 1.9 through 1.9.1, when the LDAP
    back end is used, allows remote attackers to cause a
    denial of service (assertion failure and daemon exit)
    via unspecified vectors, related to the locked_check_p
    function. NOTE: the Berkeley DB vector is covered by
    CVE-2011-4151. (CVE-2011-1528)

  - The lookup_lockout_policy function in the Key
    Distribution Center (KDC) in MIT Kerberos 5 (aka krb5)
    1.8 through 1.8.4 and 1.9 through 1.9.1, when the db2
    (aka Berkeley DB) or LDAP back end is used, allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and daemon crash) via vectors that
    trigger certain process_as_req errors. (CVE-2011-1529)

  - The krb5_db2_lockout_audit function in the Key
    Distribution Center (KDC) in MIT Kerberos 5 (aka krb5)
    1.8 through 1.8.4, when the db2 (aka Berkeley DB) back
    end is used, allows remote attackers to cause a denial
    of service (assertion failure and daemon exit) via
    unspecified vectors, a different vulnerability than
    CVE-2011-1528. (CVE-2011-4151)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_input_validation_vulnerabilities_in
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96c48069"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:kerberos");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/02");
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

if (solaris_check_release(release:"0.5.11-0.175.1.0.0.0.0", sru:"SRU 0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : kerberos\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "kerberos");
