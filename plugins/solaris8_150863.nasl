#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(72144);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:33:50 $");

  script_cve_id("CVE-2003-1067", "CVE-2013-1067");
  script_bugtraq_id(7991);
  script_osvdb_id(16004, 16005);

  script_name(english:"Solaris 8 (sparc) : 150863-01");
  script_summary(english:"Check for patch 150863-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 150863-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Localization (L10N)). Supported versions
that are affected are 8 and 9. Easily exploitable vulnerability
requiring logon to Operating System. Successful attack of this
vulnerability can result in unauthorized Operating System takeover
including arbitrary code execution. Note: Applies only when Solaris is
running on SPARC platform."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/150863-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"150863-01", obsoleted_by:"", package:"SUNWhbcp", version:"8.0,REV=1999.10.12.16.26") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"150863-01", obsoleted_by:"", package:"SUNWcbcp", version:"8.0,REV=1999.10.12.16.33") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"150863-01", obsoleted_by:"", package:"SUNWkbcp", version:"8.0,REV=1999.10.12.16.19") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
