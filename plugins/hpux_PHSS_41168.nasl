#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_41168. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47149);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798", "CVE-2010-1321");
  script_bugtraq_id(24653, 24655, 24657, 40235);
  script_osvdb_id(36595, 36596, 36597, 64744);
  script_xref(name:"HP", value:"emr_na-c02257427");
  script_xref(name:"HP", value:"HPSBUX02544");
  script_xref(name:"HP", value:"SSRT100107");

  script_name(english:"HP-UX PHSS_41168 : HP-UX Running Kerberos, Remote Denial of Service (DoS), Execution of Arbitrary Code (HPSBUX02544 SSRT100107 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 KRB5-Client Version 1.3.5.03 Cumulative patch : 

Potential security vulnerabilities have been identified on HP-UX
running Kerberos. These vulnerabilities could be exploited by remote
unauthenticated users to create a Denial of Service (DoS) or to
execute arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02257427
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51891b30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_41168 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since PHSS_41168 applies to a different OS release.");
}

patches = make_list("PHSS_41168", "PHSS_41775");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"KRB5-Client.KRB5-64SLIB", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-ENG-A-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-IA32SLIB", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-IA64SLIB", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-JPN-E-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-JPN-S-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-PRG", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-RUN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-SHLIB", version:"B.11.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
