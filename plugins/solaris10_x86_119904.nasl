#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(19371);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/08/30 00:11:54 $");

  script_cve_id("CVE-2005-4796");

  script_name(english:"Solaris 10 (x86) : 119904-02");
  script_summary(english:"Check for patch 119904-02");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119904-02"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Openwindows 3.7.3_x86: Xview Patch.
Date this patch was last updated by Sun : Aug/11/06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119904-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119904-02", obsoleted_by:"", package:"SUNWolrte", version:"3.7.3,REV=1.2004.06.28") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report());
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
