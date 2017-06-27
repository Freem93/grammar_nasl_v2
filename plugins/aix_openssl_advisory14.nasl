#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84880);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/22 16:56:37 $");

  script_cve_id(
    "CVE-2014-8176",
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-4000"
  );
  script_bugtraq_id(
    74733,
    75154,
    75156,
    75157,
    75158,
    75159,
    75161
  );
  script_osvdb_id(
    122331,
    122875,
    123172,
    123173,
    123174,
    123175,
    123176
  );

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory14.asc (Logjam)");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
multiple vulnerabilities :

  - An invalid free memory error exists due to improper
    validation of user-supplied input when a DTLS peer
    receives application data between ChangeCipherSpec and
    Finished messages. A remote attacker can exploit this to
    corrupt memory, resulting in a denial of service or
    the execution of arbitrary code. (CVE-2014-8176)

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing inner
    'EncryptedContent'. This allows a remote attacker, via
    specially crafted ASN.1-encoded PKCS#7 blobs with
    missing content, to cause a denial of service condition
    or other potential unspecified impacts. (CVE-2015-1790)

  - A double-free error exists due to a race condition that
    occurs when a NewSessionTicket is received by a
    multi-threaded client when attempting to reuse a
    previous ticket. (CVE-2015-1791)

  - A denial of service vulnerability exists in the CMS code
    due to an infinite loop that occurs when verifying a
    signedData message. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-1792)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory14.asc");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/marketing/iwm/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

#0.9.8.2505
if (aix_check_ifix(release:"5.3", patch:"IV74809s9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2505") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV74809s9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2505") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV74809s9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2505") < 0) flag++;

#12.9.8.2505
if (aix_check_ifix(release:"5.3", patch:"IV74809s9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2505") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV74809s9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2505") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV74809s9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2505") < 0) flag++;

# Check 1.0.1 versions only after other two pass, this one has the
# potential to audit out early.
if (flag == 0)
{
  #1.0.1.514
  # ifix on POWER8 machines is IV75570m9a. ifix on all others is IV74809s9a
  aix_processor = get_kb_item("Host/AIX/processor");
  if (empty_or_null(aix_processor)) audit(AUDIT_KB_MISSING, "Host/AIX/processor");
  ifix = "(IV74809s9a|IV75570m9a)";
  if ("POWER8" >< aix_processor) ifix = "IV75570m9a";
  if (aix_check_ifix(release:"5.3", patch:ifix, package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.514") < 0) flag++;
  if (aix_check_ifix(release:"6.1", patch:ifix, package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.514") < 0) flag++;
  if (aix_check_ifix(release:"7.1", patch:ifix, package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.514") < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_extra);
  else security_hole(0);
  exit(0);
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base");
}
