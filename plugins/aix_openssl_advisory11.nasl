#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory11.asc.
#

include("compat.inc");

if (description)
{
  script_id(78772);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567");
  script_bugtraq_id(70574, 70584, 70586);
  script_osvdb_id(113251, 113373, 113374);

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory11.asc (POODLE)");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is affected by the
following vulnerabilities :

  - An error exists related to DTLS SRTP extension handling
    and specially crafted handshake messages that can allow
    denial of service attacks via memory leaks.
    (CVE-2014-3513)

  - A man-in-the-middle (MitM) information disclosure
    vulnerability known as POODLE. The vulnerability is due
    to the way SSL 3.0 handles padding bytes when decrypting
    messages encrypted using block ciphers in cipher block
    chaining (CBC) mode. MitM attackers can decrypt a
    selected byte of a cipher text in as few as 256 tries if
    they are able to force a victim application to
    repeatedly send the same data over newly created SSL 3.0
    connections. (CVE-2014-3566)

  - An error exists related to session ticket handling that
    can allow denial of service attacks via memory leaks.
    (CVE-2014-3567)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory11.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.1-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

IMPORTANT : If possible, it is recommended that a mksysb backup of the
system be created. Verify that it is both bootable and readable before
proceeding.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

#0.9.8.2503
if (aix_check_ifix(release:"5.3", patch:"IV66250s9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2503") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV66250s9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2503") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV66250s9b", package:"openssl.base", minfilesetver:"0.0.0.0", maxfilesetver:"0.9.8.2503") < 0) flag++;

#1.0.1.512
if (aix_check_ifix(release:"5.3", patch:"IV66250s9a", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.512") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV66250s9a", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.512") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV66250s9a", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.512") < 0) flag++;

#12.9.8.2503
if (aix_check_ifix(release:"5.3", patch:"IV66250s9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2503") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV66250s9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2503") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV66250s9c", package:"openssl.base", minfilesetver:"12.0.0.0", maxfilesetver:"12.9.8.2503") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
