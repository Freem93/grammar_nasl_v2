#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_36286. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26152);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/03/19 14:42:13 $");

  script_cve_id("CVE-2007-1216");
  script_bugtraq_id(23282);
  script_osvdb_id(34104, 34105, 34106);
  script_xref(name:"HP", value:"emr_na-c01056923");
  script_xref(name:"HP", value:"HPSBUX02217");
  script_xref(name:"HP", value:"SSRT071337");

  script_name(english:"HP-UX PHSS_36286 : HP-UX running Kerberos, Remote Arbitrary Code Execution (HPSBUX02217 SSRT071337 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 KRB5-Client Version 1.0 cumulative patch : 

A potential security vulnerability has been identified on HP-UX
running Kerberos. The vulnerability could be exploited by remote
authorized users to execute arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01056923
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?adb5d4c3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_36286 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_36286 applies to a different OS release.");
}

patches = make_list("PHSS_36286", "PHSS_39774", "PHSS_41166");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"KRB5-Client.KRB5-64SLIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-JPN-E-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-JPN-S-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-PRG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-RUN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-SHLIB", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
