#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_44149. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(86118);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/24 14:01:16 $");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1997", "CVE-2013-2002", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063");
  script_xref(name:"HP", value:"emr_na-c04341797");

  script_name(english:"HP-UX PHSS_44149 : s700_800 11.23 X/Motif Runtime Patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 X/Motif Runtime Patch : 

Potential security vulnerabilities has been identified with HP-UX
running the X Windows Service libraries. These vulnerabilities could
be exploited remotely to create a Denial of Service (DoS) or execute
arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c04341797
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?050a1086"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_44149 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHSS_44149 applies to a different OS release.");
}

patches = make_list("PHSS_44149");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"X11.MOTIF-SHLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"X11.MOTIF-SHLIB-IA", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"X11.X11R6-SHLIBS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"X11.X11R6-SLIBS-IA", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
