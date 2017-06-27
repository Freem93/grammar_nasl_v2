#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory4.asc.
#

include("compat.inc");

if (description)
{
  script_id(88058);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/02/07 05:42:18 $");

  script_cve_id("CVE-2015-5219", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7850", "CVE-2015-7853", "CVE-2015-7855");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"AIX 7.2 TL 0 : ntp (IV79945)");
  script_summary(english:"Check for APAR IV79945");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Network Time Protocol (NTP) is vulnerable to a denial of service,
caused by an error in the sntp program. By sending specially crafted
NTP packets, a remote attacker from within the local network could
exploit this vulnerability to cause the application to enter into an
infinite loop. Network Time Protocol (NTP) is vulnerable to a denial
of service, caused by an error in ntp_crypto.c. An attacker could
exploit this vulnerability using a packet containing an extension
field with an invalid value for the length of its value field to cause
ntpd to crash. Network Time Protocol (NTP) is vulnerable to a denial
of service, caused by an error in ntp_crypto.c. An attacker could
exploit this vulnerability using a packet containing an extension
field with an invalid value for the length of its value field to cause
ntpd to crash. Network Time Protocol (NTP) could allow a remote
attacker to obtain sensitive information, caused by a memory leak in
CRYPTO_ASSOC. An attacker could exploit this vulnerability to obtain
sensitive information. Network Time Protocol (NTP) is vulnerable to a
denial of service, caused by an error in ntp_crypto.c. An attacker
could exploit this vulnerability using a packet containing an
extension field with an invalid value for the length of its value
field to cause ntpd to crash. Network Time Protocol (NTP) is
vulnerable to a denial of service, caused by an error in the remote
configuration functionality. By sending a specially crafted
configuration file, an attacker could exploit this vulnerability to
cause the application to enter into an infinite loop. Network Time
Protocol (NTP) is vulnerable to a buffer overflow, caused by improper
bounds checking by the refclock of ntpd. By sending an overly long
string, a remote attacker could overflow a buffer and execute
arbitrary code on the system or cause the application to crash.
Network Time Protocol (NTP) is vulnerable to a denial of service,
caused by ASSERT botch instead of returning FAIL on some invalid
values by the decodenetnum() function. An attacker could exploit this
vulnerability to cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory4.asc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"7.2", ml:"00", sp:"01", patch:"IV79945s1a", package:"bos.net.tcp.ntp", minfilesetver:"7.2.0.0", maxfilesetver:"7.2.0.0") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"00", sp:"01", patch:"IV79945s1a", package:"bos.net.tcp.ntpd", minfilesetver:"7.2.0.0", maxfilesetver:"7.2.0.0") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
