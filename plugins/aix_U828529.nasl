#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U828529. The text itself is copyright (C)
# International Business Machines Corp.
#

include("compat.inc");

if (description)
{
  script_id(41850);
  script_version ("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/14 01:05:26 $");

  script_name(english:"AIX 6.1 TL 1 : bos.net.tcp.server (U828529)");
  script_summary(english:"Check for PTF U828529");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U828529, which is related to the
security of the package bos.net.tcp.server.

AIX 'named' is an implementation of BIND (Berkeley Internet Name
Domain) providing server functionality for the Domain Name System
(DNS) Protocol. AIX currently ships and supports three versions of
BIND: 4, 8, and 9.

There is an error in the handling of dynamic update messages in BIND
9. A crafted update packet from a remote user can cause a master
server to assert and exit. The successful exploitation of this
vulnerability allows a remote, unauthenticated user to make a master
DNS server assert and exit.

The following command is vulnerable :

/usr/sbin/named9."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ56316"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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

if ( aix_check_patch(ml:"610001", patch:"U828529", package:"bos.net.tcp.server.6.1.1.6") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
