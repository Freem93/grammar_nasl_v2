#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_37141. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29200);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2005-3352", "CVE-2005-3357", "CVE-2006-3747", "CVE-2007-3872", "CVE-2007-6204", "CVE-2007-6343", "CVE-2008-0212");
  script_bugtraq_id(15834, 16152, 19204);
  script_osvdb_id(21705, 22261, 27588, 38935, 39527, 39529, 39530, 39531, 39532);
  script_xref(name:"TRA", value:"TRA-2007-09");
  script_xref(name:"HP", value:"emr_na-c01112038");
  script_xref(name:"IAVT", value:"2007-T-0033");
  script_xref(name:"HP", value:"emr_na-c01188923");
  script_xref(name:"HP", value:"emr_na-c01218087");
  script_xref(name:"HP", value:"emr_na-c01321117");
  script_xref(name:"HP", value:"emr_na-c01428449");
  script_xref(name:"HP", value:"SSRT061260");
  script_xref(name:"HP", value:"SSRT061261");
  script_xref(name:"HP", value:"SSRT071293");
  script_xref(name:"HP", value:"SSRT071319");
  script_xref(name:"HP", value:"SSRT071420");

  script_name(english:"HP-UX PHSS_37141 : s700_800 11.X OV NNM6.4x/ET2.0x Intermediate Patch 17");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM6.4x/ET2.0x Intermediate Patch 17 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential vulnerabilities have been identified with HP
    OpenView Network Node Manager (OV NNM) running Apache.
    These vulnerabilities could be exploited remotely
    resulting in cross site scripting (XSS), Denial of
    Service (DoS), or execution of arbitrary code.
    (HPSBMA02328 SSRT071293)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). This
    vulnerability could be exploited remotely by an
    unauthorized user to execute arbitrary code with the
    permissions of the NNM server. (HPSBMA02281 SSRT061261)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM) running Shared
    Trace Service. The vulnerability could be remotely
    exploited to execute arbitrary code. (HPSBMA02242
    SSRT061260)

  - A potential security vulnerability has been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to create a
    Denial of Service (DoS). (HPSBMA02307 SSRT071420)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). This
    vulnerability could by exploited remotely to allow cross
    site scripting (XSS). (HPSBMA02283 SSRT071319)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-09");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01112038
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?149b8149"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01188923
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3312cdf1"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01218087
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d908af80"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01321117
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71f7c351"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01428449
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69af359a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_37141 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView Network Node Manager OpenView5.exe CGI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(79, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.00 11.11"))
{
  exit(0, "The host is not affected since PHSS_37141 applies to a different OS release.");
}

patches = make_list("PHSS_37141", "PHSS_37757");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-CORE", version:"B.02.00.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-CORE", version:"B.02.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-IPV6", version:"B.02.00.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-IPV6", version:"B.02.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-JPN", version:"B.02.00.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-JPN", version:"B.02.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVMIB-CONTRIB", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVMIB-CONTRIB", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNM-RUN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNM-RUN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-JPN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-JPN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVRPT-RUN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVRPT-RUN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-JPN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-JPN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVDB-RUN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVDB-RUN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVEVENT-MIN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVEVENT-MIN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVMIN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVMIN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVSNMP-MIN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVSNMP-MIN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-EVNT", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-EVNT", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-FW", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-FW", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-SRV", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-SRV", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatformDevKit.OVWIN-PRG", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatformDevKit.OVWIN-PRG", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.06.41.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVMIN-MAN", version:"B.06.40.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVMIN-MAN", version:"B.06.41.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
