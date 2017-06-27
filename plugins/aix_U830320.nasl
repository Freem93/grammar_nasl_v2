#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U830320. The text itself is copyright (C)
# International Business Machines Corp.
#

include("compat.inc");

if (description)
{
  script_id(52083);
  script_version ("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/14 01:05:26 $");

  script_name(english:"AIX 7.1 : printers.rte (U830320)");
  script_summary(english:"Check for PTF U830320");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U830320, which is related to the
security of the package printers.rte."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IZ85987"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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

if ( aix_check_patch(ml:"710000", patch:"U830320", package:"printers.rte.7.1.0.1") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
