#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory xntpd_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(63802);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/14 15:38:17 $");

  script_cve_id("CVE-2009-3563");
  script_xref(name:"CERT", value:"568372");

  script_name(english:"AIX 5.3 TL 10 : xntpd (IZ71608)");
  script_summary(english:"Check for APAR IZ71608");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'NTP mode 7 (MODE_PRIVATE) is used by the ntpdc query and control
utility. In contrast, ntpq uses NTP mode 6 (MODE_CONTROL), while
routine NTP time transfers use modes 1 through 5. Upon receipt of an
incorrect mode 7 request or a mode 7 error response from an address
that is not listed in a 'restrict ... noquery' or 'restrict ...
ignore' segment, ntpd will reply with a mode 7 error response and log
a message.'

'If an attacker spoofs the source address of ntpd host A in a mode 7
response packet sent to ntpd host B, both A and B will continuously
send each other error responses, for as long as those packets get
through.'

'If an attacker spoofs an address of ntpd host A in a mode 7
response packet sent to ntpd host A, then host A will
respond to itself endlessly, consuming CPU and logging
excessively.'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/xntpd_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"5.3", ml:"10", patch:"IZ71608_10", package:"bos.net.tcp.client", minfilesetver:"5.3.10.0", maxfilesetver:"5.3.10.2") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
