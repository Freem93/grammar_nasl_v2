#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory nettcp_advisory2.asc.
#

include("compat.inc");

if (description)
{
  script_id(94180);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/13 17:29:26 $");

  script_cve_id("CVE-2015-7575", "CVE-2016-0266");

  script_name(english:"AIX 5.3 TL 12 : nettcp (IV88959) (SLOTH)");
  script_summary(english:"Check for APAR IV88959");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7575 The TLS
protocol could allow weaker than expected security caused by a
collision attack when using the MD5 hash function for signing a
ServerKeyExchange message during a TLS handshake. An attacker could
exploit this vulnerability using man-in-the-middle techniques to
impersonate a TLS server and obtain credentials. IBM AIX does not
require the newest version of TLS by default which could allow a
remote attacker to obtain sensitive information using man in the
middle techniques."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/nettcp_advisory2.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"5.3", ml:"12", sp:"09", patch:"IV88959m9a", package:"bos.net.tcp.client", minfilesetver:"5.3.12.0", maxfilesetver:"5.3.12.10") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"12", sp:"09", patch:"IV88959m9a", package:"bos.net.tcp.server", minfilesetver:"5.3.12.0", maxfilesetver:"5.3.12.6") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
