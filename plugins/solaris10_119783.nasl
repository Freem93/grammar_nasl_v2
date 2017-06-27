#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(25541);
  script_version("$Revision: 1.58 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_cve_id("CVE-2007-2926", "CVE-2009-0696", "CVE-2013-0415", "CVE-2014-0591");
  script_bugtraq_id(64801);
  script_osvdb_id(101973);

  script_name(english:"Solaris 10 (sparc) : 119783-40");
  script_summary(english:"Check for patch 119783-40");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119783-40"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Sun Products Suite
(subcomponent: Bind/Postinstall script for Bind package). The
supported version that is affected is 10. Very difficult to exploit
vulnerability requiring logon to Operating System plus additional
login/authentication to component or subcomponent. Successful attack
of this vulnerability can escalate attacker privileges resulting in
unauthorized Operating System takeover including arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119783-40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119783-40", obsoleted_by:"", package:"SUNWbind", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119783-40", obsoleted_by:"", package:"SUNWbindS", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119783-40", obsoleted_by:"", package:"SUNWbindr", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
