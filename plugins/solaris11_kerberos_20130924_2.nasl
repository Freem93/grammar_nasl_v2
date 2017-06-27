#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80653);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/19 14:37:27 $");

  script_cve_id("CVE-2010-1322", "CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021", "CVE-2011-0284");

  script_name(english:"Oracle Solaris Third-Party Patch Update : kerberos (cve_2010_1322_improper_input)");
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

  - The merge_authdata function in kdc_authdata.c in the Key
    Distribution Center (KDC) in MIT Kerberos 5 (aka krb5)
    1.8.x before 1.8.4 does not properly manage an index
    into an authorization-data list, which allows remote
    attackers to cause a denial of service (daemon crash),
    or possibly obtain sensitive information, spoof
    authorization, or execute arbitrary code, via a TGS
    request that triggers an uninitialized pointer
    dereference, as demonstrated by a request from a Windows
    Active Directory client. (CVE-2010-1322)

  - MIT Kerberos 5 (aka krb5) 1.3.x, 1.4.x, 1.5.x, 1.6.x,
    1.7.x, and 1.8.x through 1.8.3 does not properly
    determine the acceptability of checksums, which might
    allow remote attackers to modify user-visible prompt
    text, modify a response to a Key Distribution Center
    (KDC), or forge a KRB-SAFE message via certain checksums
    that (1) are unkeyed or (2) use RC4 keys.
    (CVE-2010-1323)

  - MIT Kerberos 5 (aka krb5) 1.7.x and 1.8.x through 1.8.3
    does not properly determine the acceptability of
    checksums, which might allow remote attackers to forge
    GSS tokens, gain privileges, or have unspecified other
    impact via (1) an unkeyed checksum, (2) an unkeyed PAC
    checksum, or (3) a KrbFastArmoredReq checksum based on
    an RC4 key. (CVE-2010-1324)

  - MIT Kerberos 5 (aka krb5) 1.8.x through 1.8.3 does not
    reject RC4 key-derivation checksums, which might allow
    remote authenticated users to forge a (1) AD-SIGNEDPATH
    or (2) AD-KDC-ISSUED signature, and possibly gain
    privileges, by leveraging the small key space that
    results from certain one-byte stream-cipher operations.
    (CVE-2010-4020)

  - The Key Distribution Center (KDC) in MIT Kerberos 5 (aka
    krb5) 1.7 does not properly restrict the use of TGT
    credentials for armoring TGS requests, which might allow
    remote authenticated users to impersonate a client by
    rewriting an inner request, aka a 'KrbFastReq forgery
    issue.' (CVE-2010-4021)

  - Double free vulnerability in the prepare_error_as
    function in do_as_req.c in the Key Distribution Center
    (KDC) in MIT Kerberos 5 (aka krb5) 1.7 through 1.9, when
    the PKINIT feature is enabled, allows remote attackers
    to cause a denial of service (daemon crash) or possibly
    execute arbitrary code via an e_data field containing
    typed data. (CVE-2011-0284)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2010_1322_improper_input
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?991fdc40"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2011_0284_resource_management
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e593eb89"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_kerberos
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a7b5715"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.11.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:kerberos");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (solaris_check_release(release:"0.5.11-0.175.1.11.0.4.0", sru:"SRU 11.1.11.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : kerberos\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "kerberos");
