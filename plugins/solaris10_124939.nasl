#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(24846);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/08/30 00:06:18 $");

  script_cve_id("CVE-2007-1419", "CVE-2013-3837");
  script_bugtraq_id(63080);
  script_osvdb_id(98503);

  script_name(english:"Solaris 10 (sparc) : 124939-05");
  script_summary(english:"Check for patch 124939-05");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 124939-05"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Cacao). Supported versions that are
affected are 10 and 11.1. Difficult to exploit vulnerability allows
successful unauthenticated network attacks via SNMP. Successful attack
of this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Solaris.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Cacao). Supported versions that are
affected are 10 and 11.1. Difficult to exploit vulnerability allows
successful unauthenticated network attacks via SNMP. Successful attack
of this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Solaris."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/124939-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"124939-05", obsoleted_by:"", package:"SUNWjdmk-base", version:"5.1,REV=34.20060120") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");