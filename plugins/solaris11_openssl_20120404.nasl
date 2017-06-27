#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80715);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027", "CVE-2012-0050");

  script_name(english:"Oracle Solaris Third-Party Patch Update : openssl (cve_2012_0050_denial_of)");
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

  - The DTLS implementation in OpenSSL before 0.9.8s and 1.x
    before 1.0.0f performs a MAC check only if certain
    padding is valid, which makes it easier for remote
    attackers to recover plaintext via a padding oracle
    attack. (CVE-2011-4108)

  - Double free vulnerability in OpenSSL 0.9.8 before
    0.9.8s, when X509_V_FLAG_POLICY_CHECK is enabled, allows
    remote attackers to have an unspecified impact by
    triggering failure of a policy check. (CVE-2011-4109)

  - The SSL 3.0 implementation in OpenSSL before 0.9.8s and
    1.x before 1.0.0f does not properly initialize data
    structures for block cipher padding, which might allow
    remote attackers to obtain sensitive information by
    decrypting the padding data sent by an SSL peer.
    (CVE-2011-4576)

  - OpenSSL before 0.9.8s and 1.x before 1.0.0f, when RFC
    3779 support is enabled, allows remote attackers to
    cause a denial of service (assertion failure) via an
    X.509 certificate containing certificate-extension data
    associated with (1) IP address blocks or (2) Autonomous
    System (AS) identifiers. (CVE-2011-4577)

  - The Server Gated Cryptography (SGC) implementation in
    OpenSSL before 0.9.8s and 1.x before 1.0.0f does not
    properly handle handshake restarts, which allows remote
    attackers to cause a denial of service (CPU consumption)
    via unspecified vectors. (CVE-2011-4619)

  - The GOST ENGINE in OpenSSL before 1.0.0f does not
    properly handle invalid parameters for the GOST block
    cipher, which allows remote attackers to cause a denial
    of service (daemon crash) via crafted data from a TLS
    client. (CVE-2012-0027)

  - OpenSSL 0.9.8s and 1.0.0f does not properly support DTLS
    applications, which allows remote attackers to cause a
    denial of service (crash) via unspecified vectors
    related to an out-of-bounds read. NOTE: this
    vulnerability exists because of an incorrect fix for
    CVE-2011-4108. (CVE-2012-0050)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2012_0050_denial_of"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_openssl
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ecae356"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 4a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:openssl");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/04");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^openssl$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.4.0.6.0", sru:"SRU 4a") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : openssl\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "openssl");
