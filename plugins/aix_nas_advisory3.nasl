#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory nas_advisory3.asc.
#

include("compat.inc");

if (description)
{
  script_id(83874);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/02 13:41:58 $");

  script_cve_id(
    "CVE-2014-5352",
    "CVE-2014-5355",
    "CVE-2014-9421",
    "CVE-2014-9422",
    "CVE-2014-9423"
  );
  script_bugtraq_id(
    72494,
    72495,
    72496,
    72503,
    74042
  );
  script_osvdb_id(
    117920,
    117921,
    117922,
    117923,
    118567,
    118568,
    118569,
    118570
  );

  script_name(english:"AIX NAS Advisory : nas_advisory3.asc");
  script_summary(english:"Checks the version of the krb5 packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NAS installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Network Authentication Service (NAS) installed on
the remote AIX host is affected by the following vulnerabilities
related to Kerberos 5 :

  - Denial of service and remote code execution
    vulnerabilities exist due to security context handles
    not being properly maintained, allowing an
    authenticated, remote attacker to crash the service or
    execute arbitrary code using crafted GSSAPI traffic.
    (CVE-2014-5352)

  - A denial of service vulnerability exists due to improper
    handling of zero-byte or unterminated strings.
    (CVE-2014-5355)

  - Denial of service and remote code execution
    vulnerabilities exist which allow an authenticated,
    remote attacker to crash the service or execute
    arbitrary code using crafted, malformed XDR data.
    (CVE-2014-9421)

  - A privilege escalation vulnerability exists that allows
    an authenticated, remote attacker to gain administrative
    access via a flaw in kadmin authorization checks.
    (CVE-2014-9422)

  - An information disclosure vulnerability allows an
    attacker to gain information about process heap memory
    from NAS packets. (CVE-2014-9423)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/nas_advisory3.asc");
  script_set_attribute(attribute:"solution", value:
"Fixes are available at the 1.5.0.7 and 1.6.0.2 levels of the software
and can be downloaded from the AIX website.

For the NAS fileset level 1.5.0.7,
 apply ifix 1507c_fix.150404.epkg.Z if only krb5.client.rte is
 installed, otherwise apply 1507s_fix.150407.epkg.Z if krb5.server.rte
 is installed.

For the NAS fileset level 1.6.0.2,
 apply ifix 1602c_fix.150404.epkg.Z if only krb5.client.rte is
 installed, otherwise apply 1602s_fix.150407.epkg.Z if krb5.server.rte
 is installed.

For the NAS fileset level 1.5.0.3-1.5.0.4,
 upgrade to NAS fileset level 1.6.0.2 and apply ifix
 1602c_fix.150404.epkg.Z if only krb5.client.rte is installed,
 otherwise apply 1602s_fix.150407.epkg.Z if krb5.server.rte is
 installed.

For all other NAS fileset levels,
 upgrade to NAS fileset level 1.5.0.7 and apply ifix
 1507c_fix.150404.epkg.Z if only krb5.client.rte is installed,
 otherwise apply 1507s_fix.150407.epkg.Z if krb5.server.rte is
 installed.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mit:kerberos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AIX/version")) audit(AUDIT_OS_NOT, "AIX");
if (!get_kb_item("Host/AIX/lslpp")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_kb_item("Host/AIX/emgr_failure")) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

# 1.5.0.7, 1.6.0.2
# Check for server existence first then ifixes on latest clients
if (
  aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.6.0.2") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.6.0.2") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.6.0.2") > 0
)
{
  # Client checks with server
  if (aix_check_ifix(release:"5.3", patch:"1507s_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
  if (aix_check_ifix(release:"6.1", patch:"1507s_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
  if (aix_check_ifix(release:"7.1", patch:"1507s_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
  if (aix_check_ifix(release:"5.3", patch:"1602s_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;
  if (aix_check_ifix(release:"6.1", patch:"1602s_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;
  if (aix_check_ifix(release:"7.1", patch:"1602s_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;

}
else
{
  if (aix_check_ifix(release:"5.3", patch:"1507c_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
  if (aix_check_ifix(release:"6.1", patch:"1507c_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
  if (aix_check_ifix(release:"7.1", patch:"1507c_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
  if (aix_check_ifix(release:"5.3", patch:"1602c_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;
  if (aix_check_ifix(release:"6.1", patch:"1602c_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;
  if (aix_check_ifix(release:"7.1", patch:"1602c_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;
}

# ifix checks on latest servers
if (aix_check_ifix(release:"5.3", patch:"1507s_fix", package:"krb5.server.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"1507s_fix", package:"krb5.server.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"1507s_fix", package:"krb5.server.rte", minfilesetver:"1.5.0.7", maxfilesetver:"1.5.0.7") < 0) flag++;
if (aix_check_ifix(release:"5.3", patch:"1602s_fix", package:"krb5.server.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"1602s_fix", package:"krb5.server.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"1602s_fix", package:"krb5.server.rte", minfilesetver:"1.6.0.2", maxfilesetver:"1.6.0.2") < 0) flag++;

# All other versions, package checks
# Below 1.5.0.3
if (aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.7") > 0) flag++;
# 1.5.0.5 - 1.5.0.6
if (aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"1.5.0.5", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"1.5.0.5", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"1.5.0.5", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"1.5.0.5", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"1.5.0.5", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"1.5.0.5", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0) flag++;
# 1.5.0.3 - 1.5.0.4
if (aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.4", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.4", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.4", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.4", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.4", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.4", fixpackagever:"1.6.0.2") > 0) flag++;
# 1.6.0.0 - 1.6.0.1
if (aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0) flag++;
if (aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0) flag++;


report_note = '\n' +
  'NOTE: See solution for additional ifix patching instructions if' + '\n' +
  'fileset level is not 1.5.0.7 or 1.6.0.2.' + '\n';

if (flag)
{
  report_extra = aix_report_get() + report_note;
  if (report_verbosity > 0) security_hole(port:0, extra:report_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
