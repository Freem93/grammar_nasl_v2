#@DEPRECATED@
#
# Disabled on 2014/03/10.  Deprecated by aix_U843468.nasl, aix_U849490.nasl

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory large_send_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(64304);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/15 21:51:08 $");

  script_cve_id("CVE-2012-0194");

  script_name(english:"AIX 7.1 TL 1 : large_send (IV14211)");
  script_summary(english:"Check for APAR IV14211");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"AIX could allow a remote attacker to cause a denial of service, caused
by an error when the TCP large send offload option is enabled on a
network interface. By sending a specially crafted sequence of packets,
an attacker could exploit this vulnerability to cause a kernel panic."
  );
  # http://aix.software.ibm.com/aix/efixes/security/large_send_advisory.asc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff27e272"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, 'This plugin has been deprecated.  Use plugin #72840 (aix_U843468.nasl) and #72846 (aix_U849490.nasl) instead.');

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.1", ml:"01", sp:"02", patch:"IV14211s02", package:"bos.net.tcp.client", minfilesetver:"7.1.1.0", maxfilesetver:"7.1.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"01", sp:"03", patch:"IV14211s03", package:"bos.net.tcp.client", minfilesetver:"7.1.1.0", maxfilesetver:"7.1.1.3") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
