#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90448);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id(
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-0800",
    "CVE-2016-2842"
  );
  script_osvdb_id(
    134973,
    135095,
    135096,
    135121,
    135149,
    135150,
    135151
  );
  script_xref(name:"CERT", value:"583776");

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory18.asc / openssl_advisory19.asc (DROWN)");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
the following vulnerabilities :

  - A key disclosure vulnerability exists due to improper
    handling of cache-bank conflicts on the Intel
    Sandy-bridge microarchitecture. An attacker can exploit
    this to gain access to RSA key information.
    (CVE-2016-0702)

  - A double-free error exists due to improper validation of
    user-supplied input when parsing malformed DSA private
    keys. A remote attacker can exploit this to corrupt
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-0705)

  - A NULL pointer dereference flaw exists in the
    BN_hex2bn() and BN_dec2bn() functions. A remote attacker
    can exploit this to trigger a heap corruption, resulting
    in the execution of arbitrary code. (CVE-2016-0797)

  - A denial of service vulnerability exists due to improper
    handling of invalid usernames. A remote attacker can
    exploit this, via a specially crafted username, to leak
    300 bytes of memory per connection, exhausting available
    memory resources. (CVE-2016-0798)

  - Multiple memory corruption issues exist that allow a
    remote attacker to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-0799)

  - A flaw exists that allows a cross-protocol
    Bleichenbacher padding oracle attack known as DROWN
    (Decrypting RSA with Obsolete and Weakened eNcryption).
    This vulnerability exists due to a flaw in the Secure
    Sockets Layer Version 2 (SSLv2) implementation, and it
    allows captured TLS traffic to be decrypted. A
    man-in-the-middle attacker can exploit this to decrypt
    the TLS connection by utilizing previously captured
    traffic and weak cryptography along with a series of
    specially crafted connections to an SSLv2 server that
    uses the same private key. (CVE-2016-0800)

  - A denial of service vulnerability exists due to improper
    verification of memory allocation by the doapr_outch()
    function in file crypto/bio/b_print.c. A remote attacker
    can exploit this, via a specially crafted string, to
    write data out-of-bounds or exhaust memory resources or
    possibly have other unspecified impact. (CVE-2016-2842)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory18.asc");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory19.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

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
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit( 0, "This AIX package check is disabled because : " + get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_098 = "(IV83169m9b)";
ifixes_1298 = "(IV83169m9c)";
ifixes_101 = "(IV83169m9a)";
ifixes_102 = "(IV83169s9d)";

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

#1.0.2.500

if (aix_check_ifix(release:"5.3", patch:ifixes_102, package:"openssl.base", minfilesetver:"1.0.2.500", maxfilesetver:"1.0.2.500") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_102, package:"openssl.base", minfilesetver:"1.0.2.500", maxfilesetver:"1.0.2.500") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_102, package:"openssl.base", minfilesetver:"1.0.2.500", maxfilesetver:"1.0.2.500") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_102, package:"openssl.base", minfilesetver:"1.0.2.500", maxfilesetver:"1.0.2.500") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base");
}
