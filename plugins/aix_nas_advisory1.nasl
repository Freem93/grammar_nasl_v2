#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory nas_advisory1.asc.
#

include("compat.inc");

if (description)
{
  script_id(77532);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2014-4341", "CVE-2014-4343", "CVE-2014-4344");
  script_bugtraq_id(68909, 69159, 69160);
  script_osvdb_id(108751, 109389, 109390);

  script_name(english:"AIX NAS Advisory : nas_advisory1.asc");
  script_summary(english:"Checks the version of the krb5 packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NAS installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Network Authentication Service (NAS) installed on
the remote AIX host is affected by the following vulnerabilities
related to Kerberos 5 :

  - An attacker can cause a denial of service (buffer
    over-read and application crash) by injecting invalid
    tokens into a GSSAPI application session.
    (CVE-2014-4341)

  - An attacker with the ability to spoof packets appearing
    to be from a GSSAPI acceptor can cause a denial of
    service or execute arbitrary code by using a double-free
    condition in GSSAPI initiators (clients) which are using
    the SPNEGO mechanism, by returning a different
    underlying mechanism than was proposed by the initiator.
    (CVE-2014-4343)

  - An attacker can cause a denial of service through a NULL
    pointer dereference and application crash during a
    SPNEGO negotiation, by sending an empty token as the
    second or later context token from initiator to
    acceptor. (CVE-2014-4344)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/nas_advisory1.asc");
  script_set_attribute(attribute:"see_also", value:"http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=aixbp&lang=en_US&S_PKG=nas&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b39d08f");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

If the NAS fileset level is at 1.5.0.6, then apply the ifix
'1506_fix.140813.epkg.Z'.

If the NAS fileset level is at 1.6.0.1, then apply the ifix
'1601_fix.140813.epkg.Z'.

If the NAS fileset level is at 1.5.0.3/1.5.0.4, then upgrade to
fileset level 1.6.0.1 and apply the ifix '1601_fix.140813.epkg.Z'.

For other fileset levels, upgrade to fileset level 1.5.0.6 and apply
the ifix '1506_fix.140813.epkg.Z'.

These fixes will also be part of the next filesets of NAS versions
1.5.0.7 and 1.6.0.2.

These filesets will be made available by 14th November 2014 and can be
downloaded from the AIX website.

To extract the fixes from the tar file, use the commands : 
  tar xvf nas1_fix.tar
  cd nas1_fix

IMPORTANT : If possible, it is recommended that a mksysb backup of the
system be created. Verify that it is both bootable and readable before
proceeding.

To preview the fix installation, use the command :

 installp -a - fix_name -p all

To install the fix package, use the command :

 installp -a - fix_name -X all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(415);
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mit:kerberos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

#1.5.0.0-2
if (
  aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"1.5.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.6") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"1.5.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.6") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"1.5.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.6") > 0 ||
  aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"1.5.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.6") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"1.5.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.6") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"1.5.0.0", maxpackagever:"1.5.0.2", fixpackagever:"1.5.0.6") > 0
)
{
  flag++;
  aix_report_extra += 'Additional iFix required if not present: 1506_ifix\n';
}

#1.5.0.3-5
if (
  aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.5", fixpackagever:"1.6.0.1") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.5", fixpackagever:"1.6.0.1") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.5", fixpackagever:"1.6.0.1") > 0 ||
  aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.5", fixpackagever:"1.6.0.1") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.5", fixpackagever:"1.6.0.1") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"1.5.0.3", maxpackagever:"1.5.0.5", fixpackagever:"1.6.0.1") > 0
)
{
  flag++;
  aix_report_extra += 'Additional iFix required if not present: 1601_ifix\n';
}

#1.5.0.6
if (aix_check_ifix(release:"5.3", patch:"1506_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.6", maxfilesetver:"1.5.0.6") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"1506_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.6", maxfilesetver:"1.5.0.6") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"1506_fix", package:"krb5.client.rte", minfilesetver:"1.5.0.6", maxfilesetver:"1.5.0.6") < 0) flag++;
if (aix_check_ifix(release:"5.3", patch:"1506_fix", package:"krb5.server.rte", minfilesetver:"1.5.0.6", maxfilesetver:"1.5.0.6") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"1506_fix", package:"krb5.server.rte", minfilesetver:"1.5.0.6", maxfilesetver:"1.5.0.6") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"1506_fix", package:"krb5.server.rte", minfilesetver:"1.5.0.6", maxfilesetver:"1.5.0.6") < 0) flag++;

#1.6.0.1
if (aix_check_ifix(release:"5.3", patch:"1601_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.1", maxfilesetver:"1.6.0.1") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"1601_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.1", maxfilesetver:"1.6.0.1") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"1601_fix", package:"krb5.client.rte", minfilesetver:"1.6.0.1", maxfilesetver:"1.6.0.1") < 0) flag++;
if (aix_check_ifix(release:"5.3", patch:"1601_fix", package:"krb5.server.rte", minfilesetver:"1.6.0.1", maxfilesetver:"1.6.0.1") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"1601_fix", package:"krb5.server.rte", minfilesetver:"1.6.0.1", maxfilesetver:"1.6.0.1") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"1601_fix", package:"krb5.server.rte", minfilesetver:"1.6.0.1", maxfilesetver:"1.6.0.1") < 0) flag++;

aix_report = aix_report_get();
if (!isnull(aix_report_extra)) aix_report = aix_report + aix_report_extra;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
