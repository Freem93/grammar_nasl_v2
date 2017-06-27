#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22954);
  script_version("$Revision: 1.40 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0294", "CVE-2006-0295", "CVE-2006-0296", "CVE-2006-0297", "CVE-2006-0298", "CVE-2006-0299", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723", "CVE-2006-1724", "CVE-2006-1725", "CVE-2006-1726", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-3805", "CVE-2006-5463", "CVE-2006-6498", "CVE-2006-6499", "CVE-2007-1794");

  script_name(english:"Solaris 10 (sparc) : 119115-36");
  script_summary(english:"Check for patch 119115-36");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119115-36"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla 1.7 patch.
Date this patch was last updated by Sun : Sep/13/14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119115-36"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox location.QueryInterface() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 79, 94, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozapoc-adapter", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozilla-devel", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozjs-debugger", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozdom-inspector", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozmail", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmoznss-devel", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozchat", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozgm", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmoznspr", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmoznss", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozpsm", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozspell", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119115-36", obsoleted_by:"", package:"SUNWmozilla", version:"1.7,REV=10.0.3.2004.12.21.12.28") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
