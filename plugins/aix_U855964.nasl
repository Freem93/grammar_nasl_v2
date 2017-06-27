#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U855964. The text itself is copyright (C)
# International Business Machines Corp.
#

include("compat.inc");

if (description)
{
  script_id(69285);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/08/10 23:38:31 $");

  script_cve_id("CVE-2013-3035");
  script_bugtraq_id(60348);

  script_name(english:"AIX 6.1 TL 8 : bos.net.tcp.client (U855964)");
  script_summary(english:"Check for PTF U855964");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U855964, which is related to the
security of the package bos.net.tcp.client.

If an AIX machine has IPv6 address configured, and if a malformed IPv6
packet in a specific format is sent to that machine, the machine can
hang while processing that packet. The problem can happen only if an
IPv6 address is configured on any of the network interfaces."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV42124"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if ( aix_check_patch(ml:"610008", patch:"U855964", package:"bos.net.tcp.client.6.1.8.16") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
