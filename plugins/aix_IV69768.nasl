#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84264);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"AIX 6.1 TL 8 : nettcp (IV69768) (POODLE)");
  script_summary(english:"Check for APAR IV69768 or APAR IV75644.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"A man-in-the-middle (MitM) information disclosure vulnerability,
known as POODLE, exists due to the way SSL 3.0 handles padding bytes
when decrypting messages encrypted using block ciphers in cipher block
chaining (CBC) mode. A MitM attacker can decrypt a selected byte of a
cipher text in as few as 256 tries if they are able to force a victim
application to repeatedly send the same data over newly created SSL
3.0 connections.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/nettcp_advisory.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:"Install the appropriate interim fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version", "Host/AIX/oslevelsp");

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

oslevel = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevel, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
if ( oslevelparts[0] != "6100" || oslevelparts[1] != "08" || oslevelparts[2] != "06" ) audit(AUDIT_OS_NOT, "AIX 6100-08-06", "AIX " + oslevel);

flag = 0;

if (aix_check_ifix(release:"6.1", ml:"08", sp:"06", patch:"(IV69768s6a|IV75644m6a)", package:"bos.net.tcp.client", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.8.19") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"08", sp:"06", patch:"(IV69768s6a|IV75644m6a)", package:"bos.net.tcp.server", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.8.18") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_extra);
  else security_warning(0);
  exit(0);
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client / bos.net.tcp.server");
}
