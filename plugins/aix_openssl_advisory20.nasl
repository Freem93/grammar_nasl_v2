#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92323);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/08 14:39:33 $");

  script_cve_id(
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2108",
    "CVE-2016-2109",
    "CVE-2016-2176"
  );
  script_bugtraq_id(
    87940,
    89744,
    89746,
    89752,
    89757
  );
  script_osvdb_id(
    137577,
    137897,
    137898,
    137899,
    137900
  );

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory20.asc");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
the following vulnerabilities :

  - A heap buffer overflow condition exists in the
    EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in the
    EVP_EncryptUpdate() function within file
    crypto/evp/evp_enc.c that is triggered when handling a
    large amount of input data after a previous call occurs
    to the same function with a partial block. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - A remote code execution vulnerability exists in the
    ASN.1 encoder due to an underflow condition that occurs
    when attempting to encode the value zero represented as
    a negative integer. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-2108)

  - Multiple unspecified flaws exist in the d2i BIO
    functions when reading ASN.1 data from a BIO due to
    invalid encoding causing a large allocation of memory.
    An unauthenticated, remote attacker can exploit these to
    cause a denial of service condition through resource
    exhaustion. (CVE-2016-2109)

  - An out-of-bounds read error exists in the
    X509_NAME_oneline() function within file
    crypto/x509/x509_obj.c when handling very long ASN1
    strings. An unauthenticated, remote attacker can exploit
    this to disclose the contents of stack memory.
    (CVE-2016-2176)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory20.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");

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
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

#0.9.8.2507
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.9.8.401", maxpackagever:"0.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.9.8.401", maxpackagever:"0.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"0.9.8.401", maxpackagever:"0.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"0.9.8.401", maxpackagever:"0.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;

#12.9.8.2507
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"12.9.8.1100", maxpackagever:"12.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"12.9.8.1100", maxpackagever:"12.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"12.9.8.1100", maxpackagever:"12.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"12.9.8.1100", maxpackagever:"12.9.8.2506", fixpackagever:"12.9.8.2507") > 0) flag++;

#1.0.1.516
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.515", fixpackagever:"1.0.1.516") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.515", fixpackagever:"1.0.1.516") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.515", fixpackagever:"1.0.1.516") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.515", fixpackagever:"1.0.1.516") > 0) flag++;

#1.0.2.800
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.799", fixpackagever:"1.0.2.800") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.799", fixpackagever:"1.0.2.800") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.799", fixpackagever:"1.0.2.800") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.799", fixpackagever:"1.0.2.800") > 0) flag++;

#20.11.101.501
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.11.101.500", fixpackagever:"20.11.101.501") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.11.101.500", fixpackagever:"20.11.101.501") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.11.101.500", fixpackagever:"20.11.101.501") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.11.101.500", fixpackagever:"20.11.101.501") > 0) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base");
}
