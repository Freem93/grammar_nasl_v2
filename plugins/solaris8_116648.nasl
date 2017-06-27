#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23381);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/12/12 14:59:32 $");

  script_cve_id("CVE-2006-3921", "CVE-2006-4339", "CVE-2006-5201", "CVE-2006-7140", "CVE-2007-1488", "CVE-2007-1526", "CVE-2007-4164", "CVE-2008-2166", "CVE-2008-2518", "CVE-2009-1934");
  script_xref(name:"IAVB", value:"2008-B-0045");

  script_name(english:"Solaris 8 (sparc) : 116648-25");
  script_summary(english:"Check for patch 116648-25");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 116648-25"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Web Server 6.1: Sun ONE Web Server 6.1 Patch WS61SP13.
Date this patch was last updated by Sun : Sep/20/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/116648-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(79, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"116648-25", obsoleted_by:"", package:"SUNWwbsvr", version:"6.1,REV=2003.11.21.13.47") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
