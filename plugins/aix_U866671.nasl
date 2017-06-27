#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U866671. The text itself is copyright (C)
# International Business Machines Corp.
#

include("compat.inc");

if (description)
{
  script_id(91233);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id("CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241");

  script_name(english:"AIX 6.1 TL 9 : bos.rte.control (U866671)");
  script_summary(english:"Check for PTF U866671");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U866671, which is related to the
security of the package bos.rte.control.

Libxml2 is vulnerable to a denial of service, caused by a heap-based
buffer overflow in the xmlParseEntityDecl or
xmlParseConditionalSections function. By using a specially crafted XML
data, a remote attacker could exploit this vulnerability to trigger an
out-of-bounds read and cause the system to crash. Libxml2 is
vulnerable to a denial of service, caused by a heap-based buffer
overflow in the xmlParseConditionalSections function. By using a
specially crafted XML data, a remote attacker could exploit this
vulnerability to trigger an out-of-bounds read and cause the system to
crash. libxml2 is vulnerable to a buffer overflow, caused by improper
bounds checking by the XML parser in xmlNextChar. By using a malformed
XML file, a local attacker could overflow a buffer and execute
arbitrary code on the system or cause the application to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV80588"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/20");
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

if ( aix_check_patch(ml:"610009", patch:"U866671", package:"bos.rte.control.6.1.9.101") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
