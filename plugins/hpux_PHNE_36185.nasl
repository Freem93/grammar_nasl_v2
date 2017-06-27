#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_36185. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(29199);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/04/20 00:36:49 $");

  script_cve_id("CVE-2007-2930");
  script_xref(name:"HP", value:"emr_na-c01283837");
  script_xref(name:"HP", value:"HPSBUX02289");
  script_xref(name:"HP", value:"SSRT071461");

  script_name(english:"HP-UX PHNE_36185 : HP-UX Running BIND 8, Remote DNS Cache Poisoning (HPSBUX02289 SSRT071461 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 Bind 8.1.2 Patch : 

A potential vulnerability has been identified with HP-UX running BIND
8. The vulnerability could be exploited remotely to cause DNS cache
poisoning."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01283837
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?832f0c09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_36185 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_36185 applies to a different OS release.");
}

patches = make_list("PHNE_36185");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
