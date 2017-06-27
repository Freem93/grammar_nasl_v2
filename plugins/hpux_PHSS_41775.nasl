#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_41775. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(51659);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2010-1323", "CVE-2010-1324");
  script_bugtraq_id(45116, 45118);
  script_osvdb_id(69609, 69610);
  script_xref(name:"HP", value:"emr_na-c02657328");
  script_xref(name:"HP", value:"HPSBUX02623");
  script_xref(name:"HP", value:"SSRT100355");

  script_name(english:"HP-UX PHSS_41775 : HP-UX Running Kerberos, Remote Unauthorized Modification (HPSBUX02623 SSRT100355 rev.1)");
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
running Kerberos. These vulnerabilities could be exploited remotely by
an unauthorized user to modify data, prompts, or responses."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02657328
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25dff8e6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_41775 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_41775 applies to a different OS release.");
}

patches = make_list("PHSS_41775");
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
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
