#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_37865. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(33864);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2015/05/29 04:35:54 $");

  script_cve_id("CVE-2008-1447");
  script_bugtraq_id(30131);
  script_xref(name:"HP", value:"emr_na-c01506861");
  script_xref(name:"IAVA", value:"2008-A-0045");
  script_xref(name:"HP", value:"HPSBUX02351");
  script_xref(name:"HP", value:"SSRT080058");

  script_name(english:"HP-UX PHNE_37865 : HP-UX Running BIND, Remote DNS Cache Poisoning (HPSBUX02351 SSRT080058 rev.6)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Bind 9.2.0 components : 

A potential security vulnerability has been identified with HP-UX
running BIND. The vulnerability could be exploited remotely to cause
DNS cache poisoning."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01506861
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a80e2e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_37865 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/05");
  script_set_attribute(attribute:"patch_modification_date", value:"2010/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_37865 applies to a different OS release.");
}

patches = make_list("PHNE_37865", "PHNE_40089", "PHNE_40339", "PHNE_41721", "PHNE_42727", "PHNE_43096", "PHNE_43278", "PHNE_43369");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INET-JPN-E-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INET-JPN-S-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-INETD", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-RUN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
