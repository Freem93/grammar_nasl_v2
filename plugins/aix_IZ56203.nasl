#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory libC_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(64341);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/11 18:51:58 $");

  script_cve_id("CVE-2009-2669");

  script_name(english:"AIX 6.1 TL 0 : libC (IZ56203)");
  script_summary(english:"Check for APAR IZ56203");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is a an error in the handling of the _LIB_INIT_DBG and
_LIB_INIT_DBG_FILE environment variables in a debugging component of
the XL C++ runtime library. A local user can exploit this error when
executing setuid root programs linked with the XL C++ runtime library,
and thereby create arbirtrary, world writeable files owned by root.

The successful exploitation of this vulnerability allows a local user
to create arbitrary files and execute arbitrary code as the root user.

Note that in AIX 6.1 the debugging component moved from
libC.a to libc.a. This means that the fix is delivered by
updating the XL C++ runtime on AIX 5.3 and earlier, and by
updating the bos.rte.libc fileset on AIX 6.1.

The following libraries are vulnerable :

AIX 5.3 and earlier: /usr/lpp/xlC/lib/libC.a

AIX 6.1: /usr/ccs/lib/libc.a /usr/ccs/lib/libp/libc.a."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/libC_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/04");
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

if (aix_check_ifix(release:"6.1", ml:"00", patch:"IZ56203_00", package:"bos.rte.libc", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.11") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"00", patch:"IZ56203_00", package:"bos.adt.prof", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.10") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"00", patch:"IZ56203_0p", package:"bos.rte.libc", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.11") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"00", patch:"IZ56203_0p", package:"bos.adt.prof", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.10") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
