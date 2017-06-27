#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory6.asc.
#
# @DEPRECATED@
#
# Disabled on 2017/01/20. Deprecated by aix_ntp_v3_advisory6.nasl.
#

include("compat.inc");

if (description)
{
  script_id(91520);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/19 19:35:23 $");

  script_cve_id("CVE-2015-7973", "CVE-2015-7977", "CVE-2015-7979", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158");

  script_name(english:"AIX 5.3 TL 12 : ntp (IV84269) (deprecated)");
  script_summary(english:"Check for APAR IV84269");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7973 NTP could
allow a remote attacker to launch a replay attack. An attacker could
exploit this vulnerability using authenticated broadcast mode packets
to conduct a replay attack and gain unauthorized access to the system.
NTP is vulnerable to a denial of service, caused by a NULL pointer
dereference. By sending a specially crafted ntpdc reslist command, an
attacker could exploit this vulnerability to cause a segmentation
fault. NTP could allow a remote attacker to bypass security
restrictions. By sending specially crafted broadcast packets with bad
authentication, an attacker could exploit this vulnerability to cause
the target broadcast client to tear down the association with the
broadcast server. NTP could allow a remote attacker to obtain
sensitive information, caused by an origin leak in ntpq and ntpdc. An
attacker could exploit this vulnerability to obtain sensitive
information. NTP could allow a remote attacker to launch a replay
attack. An attacker could exploit this vulnerability using ntpq to
conduct a replay attack and gain unauthorized access to the system.
NTP is vulnerable to a denial of service, caused by the improper
processing of incoming packets by ntpq. By sending specially crafted
data, an attacker could exploit this vulnerability to cause the
application to enter into an infinite loop.

This plugin has been deprecated due to manual logic changes and
advisory issues. Use aix_ntp_v3_advisory6.nasl (plugin ID 92356)
instead."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory6.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_ntp_v3_advisory6.nasl (plugin ID 92356) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"5.3", ml:"12", sp:"09", patch:"IV84269m9a", package:"bos.net.tcp.client", minfilesetver:"5.3.12.0", maxfilesetver:"5.3.12.10") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
