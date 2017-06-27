#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory libc_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(64329);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/11 18:51:58 $");

  script_cve_id("CVE-2009-1786");

  script_name(english:"AIX 5.3 TL 8 : libc (IZ50447)");
  script_summary(english:"Check for APAR IZ50447");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is a race condition in the MALLOCDEBUG debugging component of
the malloc subsystem in the library libc.a. A local user can exploit
this race condition when executing setuid root programs and thereby
overwrite any file in the system.

The successful exploitation of this vulnerability allows a local user
to overwrite arbitrary files and execute arbitrary code as the root
user.

The following libraries are vulnerable :

/usr/ccs/lib/libc.a /usr/ccs/lib/libp/libc.a."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/libc_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
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

if (aix_check_ifix(release:"5.3", ml:"08", patch:"IZ50447_08", package:"bos.rte.libc", minfilesetver:"5.3.8.0", maxfilesetver:"5.3.8.5") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"08", patch:"IZ50447_08", package:"bos.adt.prof", minfilesetver:"5.3.8.0", maxfilesetver:"5.3.8.5") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
