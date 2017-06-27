#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory wparcre_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(72926);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/03/11 14:47:08 $");

  script_cve_id("CVE-2014-0899");
  script_bugtraq_id(66051);
  script_osvdb_id(104101);

  script_name(english:"AIX 7.1 TL 1 : wparcre (IV51420)");
  script_summary(english:"Check for APAR IV51420");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is missing a security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"If ftpd is run in a 5.2 or 5.3 WPAR, a non-root user who logs in via
ftp is allowed to access all files within the WPAR."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_vulnerability_in_wpar_ftp_for_aix?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?583faf6d");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/wparcre_advisory.asc");
  script_set_attribute(attribute:"solution", value:"Install the appropriate interim fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"7.1", ml:"01", sp:"08", patch:"IV51420s52", package:"vwpar.52.rte", minfilesetver:"1.1.0.0", maxfilesetver:"1.1.1.19") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"01", sp:"08", patch:"IV51420s53", package:"vwpar.53.rte", minfilesetver:"1.1.0.0", maxfilesetver:"1.1.1.8") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
