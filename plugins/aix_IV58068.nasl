#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(76078);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 15:38:17 $");

  script_cve_id("CVE-2013-5211");

  script_name(english:"AIX 6.1 TL 8 : ntp (IV58068)");
  script_summary(english:"Check for APAR IV58068");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The monlist feature in ntpd in NTP allows remote attackers to cause a
denial of service (traffic amplification) via forged (1)
REQ_MON_GETLIST or (2) REQ_MON_GETLIST_1 requests."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"6.1", ml:"08", sp:"04", patch:"IV58068s4a", package:"bos.net.tcp.client", minfilesetver:"6.1.8.0", maxfilesetver:"6.1.8.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
