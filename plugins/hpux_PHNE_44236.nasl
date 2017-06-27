#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_44236. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(82683);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/11/01 04:40:11 $");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296", "CVE-2014-9297");
  script_bugtraq_id(71757, 71758, 71761, 71762, 72583);
  script_osvdb_id(116066, 116067, 116068, 116069, 116070, 116071, 116074);
  script_xref(name:"CERT", value:"852879");
  script_xref(name:"HP", value:"emr_na-c04554677");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"HP-UX PHNE_44236 : s700_800 11.23 NTP timeservices upgrade plus utilities");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 NTP timeservices upgrade plus utilities : 

Potential security vulnerabilities have been identified with HP-UX
running NTP. These could be exploited remotely to execute code, create
a Denial of Service (DoS), or other vulnerabilities. References:
CVE-2014-9293 - Insufficient Entropy in Pseudo-Random Number Generator
(PRNG) (CWE-332) CVE-2014-9294 - Use of Cryptographically Weak PRNG
(CWE-338) CVE-2014-9295 - Stack Buffer Overflow (CWE-121)
CVE-2014-9296 - Error Conditions, Return Values, Status Codes
(CWE-389) CVE-2014-9297 - Improper Check for Unusual or Exceptional
Conditions (CWE-754) SSRT101872 VU#852879."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c04554677
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d544704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_44236 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");
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
  exit(0, "The host is not affected since PHNE_44236 applies to a different OS release.");
}

patches = make_list("PHNE_44236");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-BOOT", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
