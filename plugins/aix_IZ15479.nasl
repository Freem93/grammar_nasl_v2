#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory reboot_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(63756);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/11 18:51:58 $");

  script_cve_id("CVE-2008-1601");

  script_name(english:"AIX 5.2 TL 0 : reboot (IZ15479)");
  script_summary(english:"Check for APAR IZ15479");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The reboot command contains a stack based buffer overflow. A local
attacker in the shutdown group may exploit this overflow to execute
arbitrary code with root privileges because the command is setuid
root.

The following files are vulnerable :

/usr/sbin/reboot."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/reboot_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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

if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ15479_08", package:"bos.rte.control", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.86") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ15479_08", package:"bos.rte.control", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.96") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ15479_08", package:"bos.rte.control", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.107") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ15479_09", package:"bos.rte.control", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.86") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ15479_09", package:"bos.rte.control", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.96") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ15479_09", package:"bos.rte.control", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.107") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
