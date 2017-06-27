#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U868958. The text itself is copyright (C)
# International Business Machines Corp.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91235);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_name(english:"AIX 7.1 TL 4 : bos.net.tcp.client (U868958)");
  script_summary(english:"Check for PTF U868958");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U868958, which is related to the
security of the package bos.net.tcp.client.

Network Time Protocol (NTP) is vulnerable to a denial of service,
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
vulnerability to cause a denial of service.

ISC BIND is vulnerable to a denial of service, caused by an error in
db.c when parsing incoming responses. A remote attacker could exploit
this vulnerability to trigger a REQUIRE assertion failure and cause a
denial of service.

ISC BIND is vulnerable to a denial of service, caused by improper
bounds checking in apl_42.c. By sending specially crafted Address
Prefix List (APL) data, a remote authenticated attacker could exploit
this vulnerability to trigger an INSIST assertion failure and cause
the named process to terminate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV79944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV80191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV81281"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if ( aix_check_patch(ml:"710004", patch:"U868958", package:"bos.net.tcp.client.7.1.4.1") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
