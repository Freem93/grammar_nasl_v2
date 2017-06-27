#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_30950. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17539);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/20 00:41:03 $");

  script_xref(name:"HP", value:"HPSBUX01057");
  script_xref(name:"HP", value:"HPSBUX01068");
  script_xref(name:"HP", value:"HPSBUX01069");

  script_name(english:"HP-UX PHSS_30950 : s700_800 11.04 Webproxy server 2.1 update");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Webproxy server 2.1 update : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with Apache running on HP-UX where the vulnerability
    could be exploited remotely to create a Denial of
    Service (DoS) or to bypass access restrictions.

  - A potential security vulnerability has been identified
    with Apache running on HP-UX where a buffer overflow
    could be exploited remotely to execute arbitrary code.

  - A potential security vulnerability has been identified
    with HP-UX running Apache where the vulnerability could
    be exploited remotely to create a Denial of Service
    (DoS) or to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_30950 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_30950 applies to a different OS release.");
}

patches = make_list("PHSS_30950", "PHSS_31830", "PHSS_32362", "PHSS_33074", "PHSS_33666", "PHSS_34203", "PHSS_35111");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"HP_Webproxy.HPWEB-PX-CORE", version:"A.02.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
