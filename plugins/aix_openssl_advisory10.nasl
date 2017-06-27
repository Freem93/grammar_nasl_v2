#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssl_advisory10.asc.
#

include("compat.inc");

if (description)
{
  script_id(77603);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2014-3505",
    "CVE-2014-3506",
    "CVE-2014-3507",
    "CVE-2014-3508",
    "CVE-2014-3509",
    "CVE-2014-3510",
    "CVE-2014-3511",
    "CVE-2014-3512",
    "CVE-2014-5139"
  );
  script_bugtraq_id(
    69075,
    69076,
    69077,
    69078,
    69079,
    69081,
    69082,
    69083,
    69084
  );
  script_osvdb_id(
    109891,
    109892,
    109893,
    109894,
    109895,
    109896,
    109897,
    109898,
    109902
  );

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory10.asc");
  script_summary(english:"Checks the version of the openssl packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is affected by the
following vulnerabilities :

  - A memory double-free error exists related to handling
    DTLS packets that allows denial of service attacks.
    (CVE-2014-3505)

  - An unspecified error exists related to handling DTLS
    handshake messages that allows denial of service attacks
    due to large amounts of memory being consumed.
    (CVE-2014-3506)

  - A memory leak error exists related to handling
    specially crafted DTLS packets that allows denial of
    service attacks. (CVE-2014-3507)

  - An error exists related to 'OBJ_obj2txt' and the pretty
    printing 'X509_name_*' functions which leak stack data,
    resulting in an information disclosure. (CVE-2014-3508)

  - An error exists related to 'ec point format extension'
    handling and multithreaded clients that allows freed
    memory to be overwritten during a resumed session.
    (CVE-2014-3509)

  - A NULL pointer dereference error exists related to
    handling anonymous ECDH cipher suites and crafted
    handshake messages that allow denial of service attacks
    against clients. (CVE-2014-3510)

  - An error exists related to handling fragmented
    'ClientHello' messages that could allow a
    man-in-the-middle attacker to force usage of TLS 1.0
    regardless of higher protocol levels being supported by
    both the server and the client. (CVE-2014-3511)

  - A buffer overflow error exists related to handling
    Secure Remote Password protocol (SRP) parameters having
    unspecified impact. (CVE-2014-3512)

  - A NULL pointer dereference error exists related to
    handling Secure Remote Password protocol (SRP) that
    allows a malicious server to crash a client, resulting
    in a denial of service. (CVE-2014-5139)");

  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory10.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140806.txt");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

IMPORTANT : If possible, it is recommended that a mksysb backup of the
system be created. Verify that it is both bootable and readable before
proceeding.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

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

#0.9.8.2502
if (aix_check_ifix(release:"5.3", patch:"098_fix", package:"openssl.base", minfilesetver:"0.9.8.401", maxfilesetver:"0.9.8.2502") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"098_fix", package:"openssl.base", minfilesetver:"0.9.8.401", maxfilesetver:"0.9.8.2502") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"098_fix", package:"openssl.base", minfilesetver:"0.9.8.401", maxfilesetver:"0.9.8.2502") < 0) flag++;

#1.0.1.511
if (aix_check_ifix(release:"5.3", patch:"101_fix", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.511") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"101_fix", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.511") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"101_fix", package:"openssl.base", minfilesetver:"1.0.1.500", maxfilesetver:"1.0.1.511") < 0) flag++;

#12.9.8.2502
if (aix_check_ifix(release:"5.3", patch:"1298_fix", package:"openssl.base", minfilesetver:"12.9.8.1100", maxfilesetver:"12.9.8.2502") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"1298_fix", package:"openssl.base", minfilesetver:"12.9.8.1100", maxfilesetver:"12.9.8.2502") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"1298_fix", package:"openssl.base", minfilesetver:"12.9.8.1100", maxfilesetver:"12.9.8.2502") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
