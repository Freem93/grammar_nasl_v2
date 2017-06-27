#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory pioout_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(64310);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/11 18:51:58 $");

  script_cve_id("CVE-2007-5764");

  script_name(english:"AIX 5.2 TL 0 : pioout (IZ10840)");
  script_summary(english:"Check for APAR IZ10840");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow vulnerabilities exist in the 'printers.rte' fileset
commands listed below. A local attacker may execute arbitrary code
with root privileges because the commands are setuid root.

The following commands are vulnerable :

/usr/lib/lpd/pio/etc/pioout The fix for piomkpq for IZ01121 and
IZ01122 was not included with this fix package, therefore it has been
repackged and included as described below. A local attacker who is a
member of the printq group may execute arbitrary code with root
privileges because the piomkpq command is setuid root. The following
command is vulnerable: /usr/lib/lpd/pio/etc/piomkpq."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/pioout_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ10840_08", package:"printers.rte", minfilesetver:"5.2.0.0", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ10840_09", package:"printers.rte", minfilesetver:"5.2.0.0", maxfilesetver:"5.2.0.106") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ10840_10", package:"printers.rte", minfilesetver:"5.2.0.0", maxfilesetver:"5.2.0.106") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
