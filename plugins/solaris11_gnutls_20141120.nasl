#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80632);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2014-3465", "CVE-2014-3466", "CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");

  script_name(english:"Oracle Solaris Third-Party Patch Update : gnutls (multiple_vulnerabilities_in_gnutls)");
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

  - The gnutls_x509_dn_oid_name function in
    lib/x509/common.c in GnuTLS 3.0 before 3.1.20 and 3.2.x
    before 3.2.10 allows remote attackers to cause a denial
    of service (NULL pointer dereference) via a crafted
    X.509 certificate, related to a missing LDAP description
    for an OID when printing the DN. (CVE-2014-3465)

  - Buffer overflow in the read_server_hello function in
    lib/gnutls_handshake.c in GnuTLS before 3.1.25, 3.2.x
    before 3.2.15, and 3.3.x before 3.3.4 allows remote
    servers to cause a denial of service (memory corruption)
    or possibly execute arbitrary code via a long session id
    in a ServerHello message. (CVE-2014-3466)

  - Multiple unspecified vulnerabilities in the DER decoder
    in GNU Libtasn1 before 3.6, as used in GnutTLS, allow
    remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted ASN.1 data.
    (CVE-2014-3467)

  - The asn1_get_bit_der function in GNU Libtasn1 before 3.6
    does not properly report an error when a negative bit
    length is identified, which allows context-dependent
    attackers to cause out-of-bounds access via crafted
    ASN.1 data. (CVE-2014-3468)

  - The (1) asn1_read_value_type and (2) asn1_read_value
    functions in GNU Libtasn1 before 3.6 allows
    context-dependent attackers to cause a denial of service
    (NULL pointer dereference and crash) via a NULL value in
    an ivalue argument. (CVE-2014-3469)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_gnutls
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb8d4cfe"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.21.4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:gnutls");

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

if (empty_or_null(egrep(string:pkg_list, pattern:"^gnutls$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.21.0.4.1", sru:"SRU 11.1.21.4.1") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : gnutls\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "gnutls");
