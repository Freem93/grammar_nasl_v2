#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_42178. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56829);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/08/24 15:27:27 $");

  script_cve_id("CVE-2011-0546", "CVE-2011-0547");
  script_bugtraq_id(47824, 49014);
  script_osvdb_id(74919, 74920, 97853);
  script_xref(name:"HP", value:"emr_na-c02962262");
  script_xref(name:"IAVB", value:"2011-B-0108");
  script_xref(name:"HP", value:"HPSBUX02700");
  script_xref(name:"HP", value:"SSRT100506");

  script_name(english:"HP-UX PHCO_42178 : HP-UX running VEA, Remote Denial of Service (DoS), Execution of Arbitrary Code (HPSBUX02700 SSRT100506 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 VRTS 5.0.1 VRTSob Command Patch : 

Potential security vulnerabilities have been identified in HP-UX
running the Veritas Enterprise Administrator (VEA), which comes
bundled with VxVM. The vulnerabilities could be exploited remotely to
create a Denial of Service (DoS) or execute arbitrary code.
References: CVE-2011-0547, ZDI-CAN-1110, ZDI-CAN-1111."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02962262
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a55dd2ee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_42178 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_modification_date", value:"2011/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHCO_42178 applies to a different OS release.");
}

patches = make_list("PHCO_42178");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VRTSob.VEAS-FILESET", version:"3.3.1510.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
