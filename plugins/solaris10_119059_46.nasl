#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#

include("compat.inc");

if (description)
{
  script_id(82536);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id(
    "CVE-2005-2495",
    "CVE-2005-3099",
    "CVE-2006-3467",
    "CVE-2006-3739",
    "CVE-2007-1667",
    "CVE-2007-4070",
    "CVE-2008-5684"
  );
  script_bugtraq_id(
    14807,
    18034,
    19974,
    23300,
    32807
  );
  script_osvdb_id(
    19352,
    19699,
    27255,
    28739,
    34107,
    34108,
    34169,
    34170,
    36612,
    52532
  );

  script_name(english:"Solaris 10 (sparc) : 119059-46");
  script_summary(english:"Checks for patch 119059-46.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun security patch number 119059-46."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"X11 6.6.2: Xsun patch.
This patch addresses IAVT 2009-T-0001."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119059-46"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwsrv", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwplr", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwrtl", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwice", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwfs", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwxst", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwinc", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwfnt", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwpmn", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwplt", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwopt", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwacx", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-46", obsoleted_by:"", package:"SUNWxwman", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
