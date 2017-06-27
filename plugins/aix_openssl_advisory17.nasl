#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89829);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 21:21:38 $");

  script_cve_id("CVE-2015-3197", "CVE-2015-4000");
  script_bugtraq_id(74733, 82237);
  script_osvdb_id(133715, 122331);
  script_xref(name:"CERT", value:"257823");

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory17.asc (Logjam)");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
the following vulnerabilities :

  - A cipher algorithm downgrade vulnerability exists due to
    a flaw that is triggered when handling cipher
    negotiation. A remote attacker can exploit this to
    negotiate SSLv2 ciphers and complete SSLv2 handshakes
    even if all SSLv2 ciphers have been disabled on the
    server. Note that this vulnerability only exists if the
    SSL_OP_NO_SSLv2 option has not been disabled.
    (CVE-2015-3197)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory17.asc");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit( 0, "This AIX package check is disabled because : " + get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_098 = "(IV81287m9b|IV83169m9b)";
ifixes_1298 = "(IV81287m9c|IV83169m9c)";
ifixes_101 = "(IV81287m9a|IV83169m9a)";

#0.9.8.2506
if (aix_check_ifix(release:"5.3", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.9.8.401", maxfilesetver:"0.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.9.8.401", maxfilesetver:"0.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.9.8.401", maxfilesetver:"0.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_098, package:"openssl.base", minfilesetver:"0.9.8.401", maxfilesetver:"0.9.8.2506") < 0) flag++;

#12.9.8.2506
if (aix_check_ifix(release:"5.3", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.9.8.1100", maxfilesetver:"12.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.9.8.1100", maxfilesetver:"12.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.9.8.1100", maxfilesetver:"12.9.8.2506") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_1298, package:"openssl.base", minfilesetver:"12.9.8.1100", maxfilesetver:"12.9.8.2506") < 0) flag++;

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
