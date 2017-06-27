#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(41054);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/13 04:40:34 $");

  script_cve_id("CVE-2009-3468");
  script_bugtraq_id(36510);
  script_osvdb_id(58319);
  script_xref(name:"IAVA", value:"2009-A-0085");

  script_name(english:"Solaris 10 (x86) : 126366-16");
  script_summary(english:"Check for patch 126366-16");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 126366-16"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: CDE Desktop changes - Sola.
Date this patch was last updated by Sun : Dec/07/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/126366-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/23");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"126366-16", obsoleted_by:"", package:"SUNWdttshelp", version:"1.0,REV=10.2006.07.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"126366-16", obsoleted_by:"", package:"SUNWdttsu", version:"1.0,REV=10.2006.10.13") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
