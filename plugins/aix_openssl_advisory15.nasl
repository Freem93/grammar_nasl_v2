#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88085);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id(
    "CVE-2015-3194",
    "CVE-2015-3195",
    "CVE-2015-3196"
  );
  script_bugtraq_id(
    78622,
    78623,
    78626
  );
  script_osvdb_id(
    131038,
    131039,
    131040
  );

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory15.asc");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
multiple vulnerabilities :

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c when handling ASN.1 signatures that use the
    RSA PSS algorithm but are missing a mask generation
    function parameter. A remote attacker can exploit this
    to cause the signature verification routine to crash,
    leading to a denial of service. (CVE-2015-3194)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)

  - A race condition exists in s3_clnt.c that is triggered
    when PSK identity hints are incorrectly updated in the
    parent SSL_CTX structure when they are received by a
    multi-threaded client. A remote attacker can exploit
    this, via a crafted ServerKeyExchange message, to cause
    a double-free memory error, resulting in a denial of
    service. (CVE-2015-3196)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory15.asc");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/marketing/iwm/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_098 = "(098_ifix|IV81287m9b|IV83169m9b)";
ifixes_1298 = "(1298_ifix|IV81287m9c|IV83169m9c)";
ifixes_101 = "(101_ifix|101a_fix|IV81287m9a|IV83169m9a)";

#0.9.8.2506
if (aix_check_ifix(release:"5.3", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2506") < 0) flag++;

#12.9.8.2506
if (aix_check_ifix(release:"5.3", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2506") < 0) flag++;

#1.0.1.515
if (aix_check_ifix(release:"5.3", patch:ifixes_101, package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.515") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_101, package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.515") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_101, package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.515") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_101, package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.515") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base");
}
