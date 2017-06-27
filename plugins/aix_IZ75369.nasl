#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory pcnfsd_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(63819);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/03/12 02:35:32 $");

  script_cve_id("CVE-2010-1039");
  script_xref(name:"IAVA", value:"2010-A-0073");

  script_name(english:"AIX 6.1 TL 4 : pcnfsd (IZ75369)");
  script_summary(english:"Check for APAR IZ75369");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'An integer overflow vulnerability was reported in the rpc.pcnfsd
service within the several systems. The rpc.pcnfsd daemon handles
requests from PC-NFS clients for authentication services on remote
machines. These services include authentication for mounting and for
print spooling. The vulnerability is triggered when parsing crafted
RPC requests. A remote attacker can leverage this vulnerability by
sending a crafted RPC message to the target host, to potentially
inject and execute arbitrary code.'."
  );
  # http://www.checkpoint.com/defense/advisories/public/2010/cpai-13-May.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59da8842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/pcnfsd_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (aix_check_ifix(release:"6.1", ml:"04", patch:"IZ75369_04", package:"bos.net.nfs.client", minfilesetver:"6.1.4.0", maxfilesetver:"6.1.4.4") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
