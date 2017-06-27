# @DEPRECATED@
#
# This plugin has been deprecated. The patch has been superseded, use plugin aix_IV62807.nasl.
#
# Disabled on 2014/09/16.
#

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory malloc_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(76323);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/16 17:18:34 $");

  script_cve_id("CVE-2014-3074");
  script_bugtraq_id(68296);
  script_osvdb_id(108613);

  script_name(english:"AIX 7.1 TL 2 : malloc (IV61314)");
  script_summary(english:"Checks for APAR IV61314.");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"It has been identified that the runtime linker allows privilege
escalation via arbitrary file writes with elevated privileges
programs. When MALLOCOPTIONS and MALLOCBUCKETS environment variables
are set with bucket statistics options and by executing certain setuid
programs, a non-privileged user may able to create a root owned file
with 666 permission.

In AIX6.1 and above, a local user can also exploit this error using
the _LIB_INIT_DBG and _LIB_INIT_DBG_FILE environment variables.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/malloc_advisory.asc");
  script_set_attribute(attribute:"solution", value:"Install the appropriate interim fix.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/01");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Use aix_IV62807.nasl (plugin #77265) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.1", ml:"02", sp:"04", patch:"IV61314s4a", package:"bos.rte.libc", minfilesetver:"7.1.2.0", maxfilesetver:"7.1.2.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
