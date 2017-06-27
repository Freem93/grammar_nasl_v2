#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ftpd_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(63824);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/27 17:20:53 $");

  script_cve_id("CVE-2010-3187");

  script_name(english:"AIX 5.3 TL 11 : ftpd (IZ83275)");
  script_summary(english:"Check for APAR IZ83275");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is a buffer overflow vulnerability in the ftp server. By issuing
an overly long NLST command, an attacker may cause a buffer overflow. 

The successful exploitation of this vulnerability allows a remote
attacker to get the DES encrypted user hashes off the server if FTP is
configured to allow write access using Anonymous account or another
account that is available to the attacker.

The following executable is vulnerable :

/usr/sbin/ftpd."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.exploit-db.com/exploits/14456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.exploit-db.com/exploits/14409/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ftpd_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/25");
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

if (aix_check_ifix(release:"5.3", ml:"11", patch:"IZ83275_11", package:"bos.net.tcp.client", minfilesetver:"5.3.11.0", maxfilesetver:"5.3.11.4") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
