#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88591);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 21:21:38 $");

  script_cve_id("CVE-2015-7575");
  script_bugtraq_id(79684);
  script_osvdb_id(132305);

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory16.asc (SLOTH)");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by a collision-based forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by a collision-based forgery vulnerability, known as SLOTH
(Security Losses from Obsolete and Truncated Transcript Hashes), in
the TLS protocol due to accepting RSA-MD5 signatures in the server
signature within the TLS 1.2 ServerKeyExchange messages during a TLS
handshake. A man-in-the-middle attacker can exploit this, via a
transcript collision attack, to impersonate a TLS server.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory16.asc");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/downloads/transcript-collisions.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/pages/attacks/SLOTH");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/05");

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

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_101 = "(101a_fix|IV81287m9a|IV83169m9a)";

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
