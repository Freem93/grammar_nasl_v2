#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U832257. The text itself is copyright (C)
# International Business Machines Corp.
#

include("compat.inc");

if (description)
{
  script_id(46470);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/14 15:38:17 $");

  script_cve_id("CVE-2009-3563");
  script_bugtraq_id(37255);

  script_name(english:"AIX 5.3 TL 8 : bos.net.tcp.client (U832257)");
  script_summary(english:"Check for PTF U832257");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U832257, which is related to the
security of the package bos.net.tcp.client.

NTP mode 7 (MODE_PRIVATE) is used by the ntpdc query and control
utility. In contrast, ntpq uses NTP mode 6 (MODE_CONTROL), while
routine NTP time transfers use modes 1 through 5. Upon receipt of an
incorrect mode 7 request or a mode 7 error response from an address
that is not listed in a 'restrict ... noquery' or 'restrict ...
ignore' segment, ntpd will reply with a mode 7 error response and log
a message.

If an attacker spoofs the source address of ntpd host A in a mode 7
response packet sent to ntpd host B, both A and B will continuously
send each other error responses, for as long as those packets get
through.

If an attacker spoofs an address of ntpd host A in a mode 7
response packet sent to ntpd host A, then host A will
respond to itself endlessly, consuming CPU and logging
excessively.
"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ68659"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AIX/oslevel", "Host/AIX/version", "Host/AIX/lslpp");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if ( aix_check_patch(ml:"530008", patch:"U832257", package:"bos.net.tcp.client.5.3.8.12") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
