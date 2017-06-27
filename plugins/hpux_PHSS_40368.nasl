#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_40368. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(44603);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/03/12 16:06:50 $");

  script_cve_id("CVE-2010-0445");
  script_osvdb_id(62268);
  script_xref(name:"HP", value:"emr_na-c01954593");
  script_xref(name:"IAVB", value:"2010-B-0010");
  script_xref(name:"HP", value:"SSRT090076");

  script_name(english:"HP-UX PHSS_40368 : HP Network Node Manager (NNM), Remote Execution of Arbitrary Commands (HPSBMA02484 SSRT090076 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM8.10 NNM 8.1x Patch 6 : 

A potential security vulnerability has been identified with HP Network
Node Manager (NNM). The vulnerability could be exploited remotely to
execute arbitrary commands."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01954593
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de4c4a7e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_40368 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/15");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23 11.31"))
{
  exit(0, "The host is not affected since PHSS_40368 applies to a different OS release.");
}

patches = make_list("PHSS_40368", "PHSS_40611", "PHSS_40884", "PHSS_41147");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCLUSTER", version:"8.11.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCOMPS", version:"8.10.050")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCUSTPOLL", version:"8.11.010")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSDEVEXTN", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSJBOSS", version:"4.03.021")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSSPIRAMS", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNNMTRAPSV", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVMIB", version:"2.02.138")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCAUSESV", version:"8.10.150")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCOMMON", version:"8.10.100")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCONFIG", version:"8.10.100")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSDISCOSV", version:"8.10.050")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEMBDDB", version:"2.02.138")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEVNT", version:"2.02.080")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEVTPSV", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSISPINET", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSLIC", version:"8.10.150")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSSNMPCO", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSSPMD", version:"2.02.138")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMBAC", version:"8.11.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMCISCO", version:"8.11.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMGEN", version:"8.10.150")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNA", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNA", version:"8.11.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNB", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNC", version:"8.11.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMOM", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMSIM", version:"8.11.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMUCMDB", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMUI", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVPERFSPIADA", version:"8.10.160")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVSTPLR", version:"8.10.160")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
