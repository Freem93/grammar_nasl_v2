#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(69904);
  script_version("$Revision: 1.91 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2013-5862", "CVE-2014-0447", "CVE-2014-6473", "CVE-2016-5553");
  script_bugtraq_id(63072, 66826, 70546);
  script_osvdb_id(98497, 105900, 113340, 120716, 129147, 145960);

  script_name(english:"Solaris 10 (sparc) : 150400-50");
  script_summary(english:"Check for patch 150400-50");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 150400-50"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Sun Systems Products
Suite (subcomponent: Filesystem). Supported versions that are affected
are 10 and 11.3. Easily exploitable vulnerability allows low
privileged attacker with logon to the infrastructure where Solaris
executes to compromise Solaris. Successful attacks require human
interaction from a person other than the attacker. Successful attacks
of this vulnerability can result in unauthorized ability to cause a
hang or frequently repeatable crash (complete DOS) of Solaris."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/150400-50"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWs9brandu", version:"11.10.0,REV=2008.04.24.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWssad", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWdcar", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWs9brandr", version:"11.10.0,REV=2008.04.24.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWefcl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWpd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWdrcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWs8brandu", version:"11.10.0,REV=2007.10.08.16.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWfss", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWs8brandr", version:"11.10.0,REV=2007.10.08.16.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWmptsas", version:"11.10.0,REV=2009.07.14.02.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWiopc", version:"11.10.0,REV=2006.07.11.11.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWpkcs11kms", version:"11.10.0,REV=2011.06.03.09.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWipoib", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWpdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.09.15.00.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWn2cp", version:"11.10.0,REV=2007.07.08.21.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"150400-50", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
