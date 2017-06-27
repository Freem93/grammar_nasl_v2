#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_39774. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(41978);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2009-0846", "CVE-2009-0847");
  script_bugtraq_id(34257, 34408, 34409);
  script_osvdb_id(53383, 53385);
  script_xref(name:"HP", value:"emr_na-c01717795");
  script_xref(name:"HP", value:"HPSBUX02421");
  script_xref(name:"HP", value:"SSRT090047");

  script_name(english:"HP-UX PHSS_39774 : HP-UX Running Kerberos, Remote Denial of Service (DoS), Execution of Arbitrary Code (HPSBUX02421 SSRT090047 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 KRB5-Client Version 1.0 cumulative patch : 

Potential security vulnerabilities have been identified on HP-UX
running Kerberos. These vulnerabilities could be exploited by remote
unauthenticated users to create a Denial of Service (DoS) or to
execute arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01717795
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd3a3461"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_39774 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"patch_modification_date", value:"2009/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_39774 applies to a different OS release.");
}

patches = make_list("PHSS_39774", "PHSS_41166");
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
