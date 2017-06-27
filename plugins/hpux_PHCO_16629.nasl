#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_16629. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17371);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/03/12 15:37:23 $");

  script_cve_id("CVE-1999-0353");
  script_osvdb_id(6792);
  script_xref(name:"HP", value:"HPSBUX9902-091");

  script_name(english:"HP-UX PHCO_16629 : s700_800 11.00 libc cumulative patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 libc cumulative patch : 

rpc.pcnfsd has an error in its use of the spool directory."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_16629 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"1998/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHCO_16629 applies to a different OS release.");
}

patches = make_list("PHCO_16629", "PHCO_17601", "PHCO_18103", "PHCO_18227", "PHCO_19090", "PHCO_19391", "PHCO_19491", "PHCO_19691", "PHCO_20555", "PHCO_20765", "PHCO_22076", "PHCO_22314", "PHCO_22923", "PHCO_23770", "PHCO_24148", "PHCO_24723", "PHCO_25707", "PHCO_25976", "PHCO_27608", "PHCO_27731", "PHCO_27774", "PHCO_28425", "PHCO_29284", "PHCO_29633", "PHCO_29956", "PHCO_32448", "PHCO_33609");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.C-MIN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.C-MIN-64ALIB", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-64SLIB", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-SHLIBS", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AUX", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AX-64ALIB", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-MIN", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
