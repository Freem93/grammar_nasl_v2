#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(64655);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/06/01 14:14:14 $");

  script_cve_id("CVE-2012-0570", "CVE-2013-0406", "CVE-2013-0408", "CVE-2013-0413", "CVE-2013-3745");
  script_bugtraq_id(61261);
  script_osvdb_id(95318);

  script_name(english:"Solaris 10 (sparc) : 147147-26");
  script_summary(english:"Check for patch 147147-26");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 147147-26"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Libraries/Libc). Supported versions that
are affected are 8, 9, 10 and 11. Easily exploitable vulnerability
requiring logon to Operating System. Successful attack of this
vulnerability can result in unauthorized ability to cause a partial
denial of service (partial DOS) of Solaris.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Kernel/IPsec). The supported version
that is affected is 10. Difficult to exploit vulnerability allows
successful unauthenticated network attacks via TCP/IP. Successful
attack of this vulnerability can result in unauthorized update, insert
or delete access to some Solaris accessible data.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: CPU performance counters drivers). The
supported version that is affected is 10. Easily exploitable
vulnerability requiring logon to Operating System plus additional
login/authentication to component or subcomponent. Successful attack
of this vulnerability can escalate attacker privileges resulting in
unauthorized Operating System hang or frequently repeatable crash
(complete DOS).

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Remote Execution Service). Supported
versions that are affected are 10 and 11. Difficult to exploit
vulnerability requiring logon to Operating System. Successful attack
of this vulnerability can result in unauthorized update, insert or
delete access to some Solaris accessible data as well as read access
to a subset of Solaris accessible data and ability to cause a partial
denial of service (partial DOS) of Solaris.

Vulnerability in the Solaris component of Oracle and Sun Systems
Products Suite (subcomponent: Libraries/Libc). Supported versions that
are affected are 8, 9, 10 and 11. Easily exploitable vulnerability
requiring logon to Operating System. Successful attack of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of Solaris."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/147147-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWipplu", version:"13.1,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWsndmr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWtsu", version:"11.10.0,REV=2006.09.28.16.26") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWusbs", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWfmdr", version:"11.10.0,REV=2006.03.29.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWefcu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWssad", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpool", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpl5v", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWftpr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"FJSVcpcu", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWusbu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWuksp", version:"11.10.0,REV=2006.04.06.02.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWuprl", version:"11.10.0,REV=2006.04.06.02.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWs9brandr", version:"11.10.0,REV=2008.04.24.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWbcp", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWefcl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWtecla", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpsm-ipp", version:"11.10.0.0,REV=2008.02.29.16.01") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWdrcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWluxd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWfruid", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.07.25.02.27") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWio-tools", version:"11.10.0,REV=2009.06.26.00.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"FJSVfmd", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWniumx", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWuacm", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWfss", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWmptsas", version:"11.10.0,REV=2009.07.14.02.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWzoner", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWwbsup", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWippcore", version:"13.1,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWuedg", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWefcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWgss", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWiscsitgtr", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWipc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWiopc", version:"11.10.0,REV=2006.07.11.11.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpkcs11kms", version:"11.10.0,REV=2011.06.03.09.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWbnuu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.09.15.00.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWofk", version:"11.10.0,REV=2010.07.14.15.40") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWperl584usr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWdrr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWuecm", version:"11.10.0,REV=2010.07.14.15.40") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWfruip", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"FJSVpiclu", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.08.04.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWatfsu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWn2cp", version:"11.10.0,REV=2007.07.08.21.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147147-26", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
