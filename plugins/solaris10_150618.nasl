#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(70442);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/30 00:11:54 $");

  script_cve_id("CVE-2013-3842");
  script_bugtraq_id(63090);
  script_osvdb_id(98506);

  script_name(english:"Solaris 10 (sparc) : 150618-02");
  script_summary(english:"Check for patch 150618-02");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 150618-02"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Oracle Configuration Manager (OCM)). The
supported version that is affected is 10. Easily exploitable
vulnerability requiring logon to Operating System. Successful attack
of this vulnerability can result in unauthorized read access to a
subset of Solaris accessible data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/150618-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150618-02", obsoleted_by:"", package:"SUNWocmr", version:"11.11,REV=2012.12.04.14.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150618-02", obsoleted_by:"", package:"SUNWocmu", version:"11.11,REV=2012.11.13.16.42") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report());
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
