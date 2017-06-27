#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_41983. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56845);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/03/12 15:42:19 $");

  script_cve_id("CVE-2011-1534");
  script_bugtraq_id(47420);
  script_osvdb_id(71967);
  script_xref(name:"HP", value:"emr_na-c02788734");
  script_xref(name:"HP", value:"SSRT100440");

  script_name(english:"HP-UX PHSS_41983 : HP Network Node Manager i (NNMi) for HP-UX, Linux, Solaris, and Windows, Remote Unauthorized Access (HPSBMA02659 SSRT100440 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM9.10 NNM 9.1x Patch 1 : 

A potential vulnerability has been identified with HP Network Node
Manager i (NNMi) for HP-UX, Linux, Solaris, and Windows. The
vulnerability could be remotely exploited resulting in unauthorized
access to NNMi processes."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02788734
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dec283b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_41983 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"patch_modification_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_41983 applies to a different OS release.");
}

patches = make_list("PHSS_41983", "PHSS_42327", "PHSS_42628", "PHSS_42788", "PHSS_43078", "PHSS_43693");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCLUSTER", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCLUSTER", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCOMPS", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCUSTPOLL", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSDEVEXTN", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNMSDEVEXTN", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPNNMTRAPSV", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCAUSESV", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCAUSESV", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCOMMON", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCOMMON", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCONFIG", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCUSTCORR", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCUSTCORR", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSDISCOSV", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSDISCOSV", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEMBDDB", version:"2.03.013")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEVTPSV", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEVTPSV", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSHA", version:"3.00.037")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSHA", version:"3.00.042")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSISPINET", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSISPINET", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSLIC", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSLIC", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSRBA", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSRBA", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSSNMPCO", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSSPICOM", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSSPMD", version:"2.03.013")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMBAC", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMBAC", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMBSM", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMBSM", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMCISCO", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMCISCO", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMGEN", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMGEN", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMINSTALL", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMINSTALL", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNA", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNA", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNB", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNC", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMNC", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMOM", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMOM", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMSIM", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMSIM", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMUCMDB", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMUCMDB", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMUI", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMUI", version:"9.10.001")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVPERFSPIADA", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVSTPLR", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNnmSiteScope.HPOVNNMSITESCOPE", version:"9.10.000")) flag++;
if (hpux_check_patch(app:"HPOvNnmSiteScope.HPOVNNMSITESCOPE", version:"9.10.001")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
