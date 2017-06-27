#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80652);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2002-2443", "CVE-2012-1016", "CVE-2013-1415");

  script_name(english:"Oracle Solaris Third-Party Patch Update : kerberos (cve_2002_2443_denial_of)");
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

  - schpw.c in the kpasswd service in kadmind in MIT
    Kerberos 5 (aka krb5) before 1.11.3 does not properly
    validate UDP packets before sending responses, which
    allows remote attackers to cause a denial of service
    (CPU and bandwidth consumption) via a forged packet that
    triggers a communication loop, as demonstrated by
    krb_pingpong.nasl, a related issue to CVE-1999-0103.
    (CVE-2002-2443)

  - The pkinit_server_return_padata function in
    plugins/preauth/pkinit/pkinit_srv.c in the PKINIT
    implementation in the Key Distribution Center (KDC) in
    MIT Kerberos 5 (aka krb5) before 1.10.4 attempts to find
    an agility KDF identifier in inappropriate
    circumstances, which allows remote attackers to cause a
    denial of service (NULL pointer dereference and daemon
    crash) via a crafted Draft 9 request. (CVE-2012-1016)

  - The pkinit_check_kdc_pkid function in
    plugins/preauth/pkinit/ pkinit_crypto_openssl.c in the
    PKINIT implementation in the Key Distribution Center
    (KDC) in MIT Kerberos 5 (aka krb5) before 1.10.4 and
    1.11.x before 1.11.1 does not properly handle errors
    during extraction of fields from an X.509 certificate,
    which allows remote attackers to cause a denial of
    service (NULL pointer dereference and daemon crash) via
    a malformed KRB5_PADATA_PK_AS_REQ AS-REQ request.
    (CVE-2013-1415)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2002_2443_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_the_pkinit
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?263ad987"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.10.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:kerberos");

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

if (empty_or_null(egrep(string:pkg_list, pattern:"^kerberos-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "kerberos");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.10.0.5.0", sru:"SRU 11.1.10.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : kerberos\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "kerberos");
