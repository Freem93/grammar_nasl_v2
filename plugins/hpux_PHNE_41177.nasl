#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_41177. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(53269);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2009-3563");
  script_osvdb_id(60847);
  script_xref(name:"HP", value:"emr_na-c02737553");
  script_xref(name:"HP", value:"HPSBUX02639");
  script_xref(name:"HP", value:"SSRT100293");

  script_name(english:"HP-UX PHNE_41177 : HP-UX Running XNTP, Remote Denial of Service (DoS) (HPSBUX02639 SSRT100293 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 NTP timeservices upgrade plus utilities : 

A potential security vulnerability has been identified with HP-UX
running XNTP. The vulnerability could be exploited remotely create a
Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02737553
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3aca40a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_41177 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_41177 applies to a different OS release.");
}

patches = make_list("PHNE_41177");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"NTP.NTP-ENG-A-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"NTP.NTP-RUN", version:"B.11.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
