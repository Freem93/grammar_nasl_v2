#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ldapauth_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(63826);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/11 18:51:59 $");

  script_cve_id("CVE-2011-1561");

  script_name(english:"AIX 6.1 TL 6 : ldapauth (IZ97416)");
  script_summary(english:"Check for APAR IZ97416");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"After installing bos.rte.security 6.1.6.4 fileset, an LDAP user will
be able to log in with an incorrect password. This occurs only when
authtype is set to ldap_auth in the /etc/security/ldap/ldap.cfg file.
Non-LDAP users can also log in with incorrect passwords if the local
users have their SYSTEM attribute in the /etc/security/user file is
set to SYSTEM = 'LDAP', or the default stanza is set to SYSTEM =
'LDAP' and local users do not have SYSTEM set in their own stanza. If
local users don't have LDAP in their SYSTEM attribute, then they will
not be affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ldapauth_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/31");
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

if (aix_check_ifix(release:"6.1", ml:"06", patch:"IZ97416s04", package:"bos.rte.security", minfilesetver:"6.1.6.4", maxfilesetver:"6.1.6.4") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
