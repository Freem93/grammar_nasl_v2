#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(15756);
  script_version("$Revision: 1.63 $");
  script_cvs_date("$Date: 2016/12/12 14:59:32 $");

  script_cve_id("CVE-2006-5073", "CVE-2007-2045", "CVE-2008-1095", "CVE-2008-1779", "CVE-2008-2121", "CVE-2009-0346", "CVE-2009-0480");
  script_bugtraq_id(29089);
  script_xref(name:"IAVT", value:"2008-T-0014");
  script_xref(name:"IAVT", value:"2008-T-0022");

  script_name(english:"Solaris 9 (sparc) : 114344-43");
  script_summary(english:"Check for patch 114344-43");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 114344-43"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: arp, dlcosmk, ip, and ipgpc Pat.
Date this patch was last updated by Sun : Mar/05/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/114344-43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 189, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/18");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWroute", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWqosx", version:"11.9.0,REV=2002.06.13.13.44") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWcarx", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWqos", version:"11.9.0,REV=2002.06.13.13.44") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWidnx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWcsxu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWcsu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWcsl", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWarc", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"114344-43", obsoleted_by:"122300-62 ", package:"SUNWidn", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
