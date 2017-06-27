#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_40339. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(46813);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2009-0696", "CVE-2009-4022", "CVE-2010-0290", "CVE-2010-0382");
  script_bugtraq_id(35848, 37118);
  script_osvdb_id(56584, 60493, 62007, 62008);
  script_xref(name:"HP", value:"emr_na-c01835108");
  script_xref(name:"HP", value:"emr_na-c02263226");
  script_xref(name:"HP", value:"HPSBUX02451");
  script_xref(name:"HP", value:"HPSBUX02546");
  script_xref(name:"HP", value:"SSRT090137");
  script_xref(name:"HP", value:"SSRT100159");

  script_name(english:"HP-UX PHNE_40339 : s700_800 11.23 BIND 9.2.0 Revision 5.0");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 BIND 9.2.0 Revision 5.0 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP-UX running BIND. The vulnerability could be
    exploited remotely to create a Denial of Service (DoS)
    and permit unauthorized disclosure of information.
    (HPSBUX02546 SSRT100159)

  - A potential security vulnerability has been identified
    with HP-UX running BIND. The vulnerability could be
    exploited remotely to create a Denial of Service (DoS).
    (HPSBUX02451 SSRT090137)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01835108
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?937b96ed"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02263226
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?237e5744"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_40339 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/28");
  script_set_attribute(attribute:"patch_modification_date", value:"2010/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_40339 applies to a different OS release.");
}

patches = make_list("PHNE_40339", "PHNE_41721", "PHNE_42727", "PHNE_43096", "PHNE_43278", "PHNE_43369");
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
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
