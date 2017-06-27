# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/12/20.
#

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56067);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/12/20 12:07:31 $");

  script_name(english:"HP-UX PHSS_28618 : HP-UX Running on HP9000 Series 700/800, Denial of Service (DoS) (HPSBUX00264 SSRT3460 rev.5) (deprecated)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 Support Tool Manager Sep 2002 Patch : 

Certain network traffic can cause programs to fail."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00905565
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f66782d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_28618 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/19");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");



include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/HP-UX/version")) exit(0, "The host is not running HP-UX.");
if (!get_kb_item("Host/HP-UX/swlist")) exit(1, "Could not obtain the list of installed packages.");

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_28618 applies to a different OS release.");
}

patches = make_list("PHSS_28618");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-CATALOGS", version:"B.11.11.08.12")) flag++;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-MAN", version:"B.11.11.08.12")) flag++;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-SHLIBS", version:"B.11.11.08.12")) flag++;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-UUT-RUN", version:"B.11.11.08.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
