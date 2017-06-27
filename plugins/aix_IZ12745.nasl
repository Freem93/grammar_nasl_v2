#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ps_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(63753);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/11 18:51:58 $");

  script_cve_id("CVE-2008-0589");

  script_name(english:"AIX 5.3 TL 0 : ps (IZ12745)");
  script_summary(english:"Check for APAR IZ12745");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information leak exists in the 'bos.rte.control' fileset commands
listed below. A local attacker may access sensitive information for
arbitrary processes. 

The following commands are vulnerable :

/usr/bin/ps."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ps_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/22");
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

if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ12745_05", package:"bos.rte.control", minfilesetver:"5.3.0.0", maxfilesetver:"5.3.0.66") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ12745_06", package:"bos.rte.control", minfilesetver:"5.3.0.0", maxfilesetver:"5.3.0.66") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
